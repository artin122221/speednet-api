"""
این فایل مسئول ساختن تنظیمات واقعی Xray (config.json) از روی لیست کاربرهای پنل،
نوشتنش روی دیسک، و ری‌استارت کردن Xray تا تغییرات (کاربر جدید، کاربر حذف‌شده،
مسدودسازی سایت) واقعاً اعمال بشه.

نکته‌ی مهم: Xray روی لوکال‌هاست (127.0.0.1) گوش می‌ده، نه روی اینترنت باز.
این nginx هست (جلوشه) که از بیرون (دامنه‌ی ریلوی، با HTTPS واقعی) درخواست‌های
وب‌ساکت رو می‌گیره و به Xray روی لوکال پاس می‌ده. همین باعث می‌شه بدون داشتن
سرور جدا، ترافیک VPN از همون دامنه‌ی ریلوی رد بشه.
"""
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from datetime import datetime, timezone

from . import db

XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG_PATH = os.environ.get("XRAY_CONFIG_PATH", "/app/xray/config.json")
VLESS_WS_PATH = os.environ.get("VLESS_WS_PATH", "/vless-ws")
VLESS_PORT = int(os.environ.get("XRAY_VLESS_PORT", "10000"))
API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))

# پورت داخلی VLESS+REALITY. برخلاف پورت بالا، این یکی باید روی 0.0.0.0 گوش بده
# (نه فقط 127.0.0.1) چون قراره از طریق TCP Proxy خودِ ریلوی مستقیم بهش وصل بشن،
# نه از پشت nginx. REALITY ترافیک رو طوری شبیه یه سایت واقعی (مثلاً مایکروسافت)
# می‌کنه که تشخیصش برای فیلترها و سیستم‌های ضدسوءاستفاده‌ی هاستینگ خیلی سخت‌تره.
REALITY_PORT = int(os.environ.get("XRAY_REALITY_PORT", "10002"))
REALITY_DEST = os.environ.get("XRAY_REALITY_DEST", "www.microsoft.com:443")
REALITY_SERVER_NAME = os.environ.get("XRAY_REALITY_SERVER_NAME", "www.microsoft.com")

_xray_process = None


def ensure_reality_keys(data):
    """اولین بار که اجرا می‌شه، یه جفت کلید x25519 برای REALITY می‌سازه و توی
    دیتابیس ذخیره‌ش می‌کنه تا دیگه عوض نشه (چون کلید عمومی داخل لینک‌هایی هست
    که قبلاً به کاربرها دادیم). دفعات بعد همون کلید قبلی رو برمی‌گردونه."""
    settings = data["settings"]
    if settings.get("reality_private_key") and settings.get("reality_public_key"):
        return
    try:
        res = subprocess.run([XRAY_BIN, "x25519"], capture_output=True, text=True, timeout=10)
        private_key, public_key = None, None
        for line in res.stdout.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if "private" in key:
                private_key = value
            elif "public" in key or "password" in key:
                public_key = value
        if private_key and public_key:
            settings["reality_private_key"] = private_key
            settings["reality_public_key"] = public_key
            settings["reality_short_id"] = secrets.token_hex(4)
            db.save(data)
    except Exception:
        pass


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,24}$")


def _sanitize_domain(raw: str):
    """ورودی دستیِ ادمین رو تمیز می‌کنه؛ اگه کسی به‌جای یه دامنه‌ی ساده چیزی مثل
    "https://youtube.com/watch" یا یه خط خالی/فاصله وارد کنه، بدون این تابع
    Xray با یه کانفیگ نامعتبر مواجه می‌شه و کلاً بالا نمیاد (یعنی هم بلاک کار
    نمی‌کنه هم کل VPN قطع می‌شه). اینجا فقط دامنه‌های واقعاً معتبر رو قبول می‌کنیم
    و بقیه رو بی‌صدا نادیده می‌گیریم."""
    if not raw:
        return None
    value = raw.strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)  # حذف http:// یا https://
    value = value.split("/")[0]  # حذف مسیر بعد از دامنه
    value = value.split("?")[0]
    value = value.split(":")[0]  # حذف پورت احتمالی
    value = value.lstrip("*.")  # wildcard دستی رو هم قبول کن ولی ساده‌ش کن
    if not value or not _DOMAIN_RE.match(value):
        return None
    return value


def build_routing_rules(settings):
    """از روی سرویس‌های انتخاب‌شده (یوتیوب، اینستاگرام و...) و دامنه‌های دلخواه،
    قوانین مسدودسازی واقعی Xray رو می‌سازه."""
    domains = []
    catalog = {s["id"]: s for s in db.DEFAULT_SERVICE_CATALOG}
    for service_id in settings.get("blocked_services", []):
        service = catalog.get(service_id)
        if service:
            domains.extend(service["domains"])

    custom = settings.get("blocked_domains", "") or ""
    for line in custom.splitlines():
        cleaned = _sanitize_domain(line)
        if cleaned:
            domains.append(cleaned)

    rules = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
    ]
    if domains:
        rules.append({
            "type": "field",
            "domain": sorted(set(domains)),
            "outboundTag": "blocked",
        })
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
    return rules


def build_config(data):
    settings = data["settings"]
    clients_ws = []
    clients_reality = []
    for user in data["users"]:
        if user.get("is_active", True):
            clients_ws.append({"id": user["uuid"], "email": user["username"]})
            clients_reality.append({
                "id": user["uuid"],
                "email": user["username"],
                "flow": "xtls-rprx-vision",
            })

    inbounds = [
        {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        },
        {
            "tag": "vless-ws",
            "listen": "127.0.0.1",
            "port": VLESS_PORT,
            "protocol": "vless",
            "settings": {"clients": clients_ws, "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": VLESS_WS_PATH},
            },
        },
    ]

    # اگه کلیدهای REALITY ساخته شده باشن (ensure_reality_keys این کارو موقع
    # شروع انجام می‌ده)، یه ورودی دوم هم اضافه می‌کنیم که ترافیکش شبیه یه سایت
    # واقعی به نظر می‌رسه و تشخیصش سخت‌تره. این باید روی 0.0.0.0 گوش بده چون از
    # طریق TCP Proxy خودِ ریلوی (نه nginx) بهش وصل می‌شن.
    if settings.get("reality_private_key"):
        inbounds.append({
            "tag": "vless-reality",
            "listen": "0.0.0.0",
            "port": REALITY_PORT,
            "protocol": "vless",
            "settings": {"clients": clients_reality, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": REALITY_DEST,
                    "xver": 0,
                    "serverNames": [REALITY_SERVER_NAME],
                    "privateKey": settings["reality_private_key"],
                    "shortIds": [settings.get("reality_short_id") or ""],
                },
            },
        })

    config = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": False, "statsInboundDownlink": False},
        },
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {"rules": build_routing_rules(settings)},
    }
    return config


def write_config(data):
    config = build_config(data)
    os.makedirs(os.path.dirname(XRAY_CONFIG_PATH), exist_ok=True)
    # قبل از نوشتن کانفیگ جدید، از کانفیگ فعلی (که تا الان کار می‌کرده) یه نسخه‌ی
    # پشتیبان نگه می‌داریم. اگه کانفیگ جدید به هر دلیلی (مثلاً یه دامنه‌ی عجیب)
    # خراب از آب دربیاد، می‌تونیم همینو برگردونیم تا کل پنل قطع نشه.
    if os.path.exists(XRAY_CONFIG_PATH):
        try:
            shutil.copyfile(XRAY_CONFIG_PATH, XRAY_CONFIG_PATH + ".bak")
        except Exception:
            pass
    with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    return config


def start_xray():
    global _xray_process
    if _xray_process is not None and _xray_process.poll() is None:
        return
    _xray_process = subprocess.Popen(
        [XRAY_BIN, "run", "-config", XRAY_CONFIG_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def stop_xray():
    global _xray_process
    if _xray_process is not None and _xray_process.poll() is None:
        _xray_process.terminate()
        try:
            _xray_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _xray_process.kill()
    _xray_process = None


def apply_and_restart(data):
    """تنظیمات جدید رو می‌نویسه و Xray رو ری‌استارت می‌کنه تا اعمال بشه.
    برای یه پنل کوچیک، ری‌استارت چند صدم‌ثانیه‌ای Xray کاملاً قابل قبوله.

    نکته‌ی مهم درباره‌ی مصرف ترافیک: چون هر بار این تابع صدا زده می‌شه (ساخت/حذف
    کاربر، تغییر مسدودسازی و...) یه پردازش کاملاً جدید از Xray بالا میاد و
    شمارنده‌های مصرفِ داخلیش از صفر شروع می‌شن، قبل از خاموش کردن Xray قدیمی
    آخرین مصرف هر کاربر رو می‌خونیم و به‌عنوان «خط پایه» ذخیره می‌کنیم تا چیزی
    از مصرف قبلی کاربرها گم نشه."""
    ensure_reality_keys(data)
    if _xray_process is not None and _xray_process.poll() is None:
        refresh_all_traffic(data)
        for user in data["users"]:
            user["traffic_baseline_bytes"] = user.get("used_traffic_bytes", 0)
            # نشست Xray داره عوض می‌شه، پس شمارنده‌ی نشست فعلی هم باید صفر بشه
            # تا تشخیص «آخرین اتصال» بعد از ری‌استارت درست کار کنه.
            user["_last_session_bytes"] = 0
        db.save(data)

    write_config(data)
    stop_xray()
    time.sleep(0.3)
    start_xray()

    # چک می‌کنیم کانفیگ جدید واقعاً بالا اومده؛ اگه Xray فوراً کرش کرده باشه
    # (مثلاً به‌خاطر یه قانون مسدودسازی خراب)، برمی‌گردیم به آخرین کانفیگ سالم
    # تا کل VPN برای همه‌ی کاربرها قطع نشه.
    time.sleep(0.5)
    if _xray_process is None or _xray_process.poll() is not None:
        backup_path = XRAY_CONFIG_PATH + ".bak"
        if os.path.exists(backup_path):
            os.replace(backup_path, XRAY_CONFIG_PATH)
            start_xray()
        raise RuntimeError(
            "تنظیمات جدید باعث خراب شدن Xray شد (احتمالاً یکی از دامنه‌های "
            "مسدودشده نامعتبر بود)؛ به‌صورت خودکار به آخرین تنظیمات سالم برگشتیم."
        )


def query_traffic(username):
    """مصرف ترافیک یه کاربر خاص رو از خود Xray (API داخلیش) می‌پرسه.
    اگه هنوز چیزی رد نشده باشه یا Xray تازه بالا اومده باشه، صفر برمی‌گرده."""
    try:
        uplink = subprocess.run(
            [XRAY_BIN, "api", "statsquery",
             "--server", f"127.0.0.1:{API_PORT}",
             "-pattern", f"user>>>{username}>>>traffic>>>uplink"],
            capture_output=True, text=True, timeout=3,
        )
        downlink = subprocess.run(
            [XRAY_BIN, "api", "statsquery",
             "--server", f"127.0.0.1:{API_PORT}",
             "-pattern", f"user>>>{username}>>>traffic>>>downlink"],
            capture_output=True, text=True, timeout=3,
        )
        total = 0
        for res in (uplink, downlink):
            if res.returncode == 0 and res.stdout.strip():
                try:
                    parsed = json.loads(res.stdout)
                    for stat in parsed.get("stat", []):
                        total += int(stat.get("value", 0))
                except (json.JSONDecodeError, ValueError):
                    pass
        return total
    except Exception:
        return 0


def refresh_all_traffic(data):
    """مصرف همه‌ی کاربرها رو از Xray می‌گیره و توی دیتابیس آپدیت می‌کنه.

    مصرف نمایش‌داده‌شده = خط پایه (مصرفی که قبل از آخرین ری‌استارت Xray ذخیره
    شده) + مصرف همین نشست فعلی Xray. این‌جوری با هر ری‌استارت (که زیاد هم اتفاق
    می‌افته) عدد مصرف صفر یا کمتر نمی‌شه."""
    for user in data["users"]:
        session_used = query_traffic(user["username"])
        baseline = user.get("traffic_baseline_bytes", 0)
        user["used_traffic_bytes"] = baseline + session_used
        # اگه مصرف این نشست نسبت به آخرین چک بیشتر شده، یعنی کاربر همین اواخر
        # واقعاً وصل بوده و داشته ترافیک رد می‌کرده؛ برای نمایش «آخرین اتصال».
        prev_session = user.get("_last_session_bytes", 0)
        if session_used > prev_session:
            user["last_seen_at"] = db.now_iso()
        user["_last_session_bytes"] = session_used
    return data


def enforce_limits(data):
    """چک می‌کنه کدوم کاربرها حجمشون تموم شده یا تاریخ انقضاشون گذشته، و اگه
    هنوز فعال بودن، خاموششون می‌کنه (is_active = False) تا دیگه نتونن با
    کانفیگشون وصل بشن. قبل از صدا زدن این تابع باید refresh_all_traffic صدا
    زده شده باشه تا used_traffic_bytes به‌روز باشه.

    اگه یه کاربر قبلاً به همین دلیل (حجم/انقضا) خاموش شده بود و الان دیگه
    توی محدودیت نیست (مثلاً ادمین حجمش رو زیاد کرده یا اعتبارش رو تمدید کرده)،
    دوباره روشنش می‌کنه — ولی اگه خودِ ادمین دستی خاموشش کرده باشه
    (disabled_reason == "manual")، دست بهش نمی‌زنه.

    برمی‌گردونه True اگه وضعیت حداقل یه کاربر عوض شده باشه (یعنی باید
    apply_and_restart صدا زده بشه تا واقعاً اعمال بشه)."""
    changed = False
    now = datetime.now(timezone.utc)
    for user in data["users"]:
        over_quota = bool(
            user.get("data_limit_bytes")
            and user.get("used_traffic_bytes", 0) >= user["data_limit_bytes"]
        )
        expired = False
        if user.get("expire_at"):
            try:
                expired = now > datetime.fromisoformat(user["expire_at"])
            except ValueError:
                expired = False
        should_block = over_quota or expired
        reason = "expired" if expired else ("quota" if over_quota else None)
        if should_block:
            if user.get("is_active", True):
                user["is_active"] = False
                user["disabled_reason"] = reason
                changed = True
        else:
            if not user.get("is_active", True) and user.get("disabled_reason") in ("quota", "expired"):
                user["is_active"] = True
                user["disabled_reason"] = None
                changed = True
    return changed


def admin_used_bytes(data, admin_username):
    """مجموع حجم مصرفیِ یه ادمین فرعی = مصرف کانفیگ‌های همین الانش +
    حجمی که از کانفیگ‌های قبلاً حذف‌شده‌ش باقی مونده (banked_used_bytes).
    این‌جوری حذف یا دوباره ساختن کانفیگ نمی‌تونه سهمیه رو آزاد کنه."""
    live_usage = sum(
        u.get("used_traffic_bytes", 0)
        for u in data.get("users", [])
        if u.get("created_by") == admin_username
    )
    admin = next((a for a in data.get("admins", []) if a["username"] == admin_username), None)
    banked = admin.get("banked_used_bytes", 0) if admin else 0
    return live_usage + banked


def enforce_admin_quotas(data):
    """هر ادمین فرعی یه سقف حجم کلی داره (برای مجموع همه‌ی کانفیگ‌هایی که
    می‌سازه). اگه مجموع مصرفشون از سقف رد بشه، یا خودِ ادمین اصلی حساب ادمین
    فرعی رو غیرفعال کرده باشه، همه‌ی کانفیگ‌های اون ادمین خاموش می‌شن؛ وقتی
    سقف دوباره بالا بره یا حساب فعال بشه، خودکار روشن می‌شن (مگر اینکه خودِ
    ادمین اصلی اون کانفیگ خاص رو دستی خاموش کرده باشه)."""
    changed = False
    for admin in data.get("admins", []):
        limit = admin.get("data_limit_bytes")
        disabled_by_owner = not admin.get("is_active", True)
        over_quota = bool(limit) and admin_used_bytes(data, admin["username"]) >= limit
        should_block = disabled_by_owner or over_quota
        reason = "admin_disabled" if disabled_by_owner else ("admin_quota" if over_quota else None)
        for u in data.get("users", []):
            if u.get("created_by") != admin["username"]:
                continue
            if should_block:
                if u.get("is_active", True):
                    u["is_active"] = False
                    u["disabled_reason"] = reason
                    changed = True
            else:
                if not u.get("is_active", True) and u.get("disabled_reason") in ("admin_quota", "admin_disabled"):
                    u["is_active"] = True
                    u["disabled_reason"] = None
                    changed = True
    return changed
