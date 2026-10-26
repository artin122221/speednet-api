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
ACCESS_LOG_PATH = os.environ.get("XRAY_ACCESS_LOG", "/tmp/xray-access.log")
VLESS_WS_PATH = os.environ.get("VLESS_WS_PATH", "/vless-ws")
VLESS_PORT = int(os.environ.get("XRAY_VLESS_PORT", "10000"))
API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))

# ورودی‌های اضافه (همه پشت nginx و روی لوکال‌هاست): هرکدوم یه «زبان» متفاوت برای
# رسیدن به سرور هستن. بعضی اپراتورها/شبکه‌ها یه نوعشونو می‌بندن و نوع دیگه رو نه؛
# پس هرچی تنوع بیشتر باشه، شانس اینکه روی شبکه‌ی هر کاربر یکیشون کار کنه بیشتره.
# مسیرها از روی همون مسیر مخفیِ VLESS ساخته می‌شن (توی start.sh هم همین‌جوریه).
VMESS_WS_PATH = os.environ.get("VMESS_WS_PATH", VLESS_WS_PATH + "-vm")
TROJAN_WS_PATH = os.environ.get("TROJAN_WS_PATH", VLESS_WS_PATH + "-tj")
HTTPUPGRADE_PATH = os.environ.get("HTTPUPGRADE_PATH", VLESS_WS_PATH + "-hu")
XHTTP_PATH = os.environ.get("XHTTP_PATH", VLESS_WS_PATH + "-xh")
VMESS_PORT = int(os.environ.get("XRAY_VMESS_PORT", "10003"))
TROJAN_PORT = int(os.environ.get("XRAY_TROJAN_PORT", "10004"))
HTTPUPGRADE_PORT = int(os.environ.get("XRAY_HTTPUPGRADE_PORT", "10005"))
XHTTP_PORT = int(os.environ.get("XRAY_XHTTP_PORT", "10006"))

# پورت داخلی VLESS+REALITY. برخلاف پورت بالا، این یکی باید روی 0.0.0.0 گوش بده
# (نه فقط 127.0.0.1) چون قراره از طریق TCP Proxy خودِ ریلوی مستقیم بهش وصل بشن،
# نه از پشت nginx. REALITY ترافیک رو طوری شبیه یه سایت واقعی (مثلاً مایکروسافت)
# می‌کنه که تشخیصش برای فیلترها و سیستم‌های ضدسوءاستفاده‌ی هاستینگ خیلی سخت‌تره.
REALITY_PORT = int(os.environ.get("XRAY_REALITY_PORT", "10002"))
REALITY_DEST = os.environ.get("XRAY_REALITY_DEST", "www.microsoft.com:443")
REALITY_SERVER_NAME = os.environ.get("XRAY_REALITY_SERVER_NAME", "www.microsoft.com")

_xray_process = None

WS_PATH_FILE = os.environ.get("WS_PATH_FILE", "/app/data/ws_path.txt")
NGINX_TEMPLATE = os.environ.get("NGINX_TEMPLATE", "/app/nginx.conf.template")
NGINX_CONF_OUT = os.environ.get("NGINX_CONF_OUT", "/etc/nginx/nginx.conf")
NGINX_RUN_DIR = os.environ.get("NGINX_RUN_DIR", "/tmp/nginx-run")
_BASE_PATH_RE = re.compile(r"^/[A-Za-z0-9_-]{6,64}$")


def set_base_path(new_path):
    """مسیر مخفیِ کانفیگ‌ها رو عوض می‌کنه (فقط موقع بازگردانی بکاپ استفاده می‌شه، تا
    لینک کانفیگ‌هایی که قبلاً به کاربرها داده شده روی پنل جدید هم دقیقاً کار کنه).
    خروجی: (ok, پیام). ورودی عمداً خیلی سخت‌گیرانه چک می‌شه چون مستقیم توی
    تنظیمات nginx نوشته می‌شه."""
    global VLESS_WS_PATH, VMESS_WS_PATH, TROJAN_WS_PATH, HTTPUPGRADE_PATH, XHTTP_PATH
    if not isinstance(new_path, str) or not _BASE_PATH_RE.match(new_path):
        return False, "مسیر داخل بکاپ معتبر نیست"
    if new_path == VLESS_WS_PATH:
        return True, ""
    os.makedirs(os.path.dirname(WS_PATH_FILE), exist_ok=True)
    tmp = WS_PATH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new_path)
    os.replace(tmp, WS_PATH_FILE)

    VLESS_WS_PATH = new_path
    VMESS_WS_PATH = new_path + "-vm"
    TROJAN_WS_PATH = new_path + "-tj"
    HTTPUPGRADE_PATH = new_path + "-hu"
    XHTTP_PATH = new_path + "-xh"

    try:
        with open(NGINX_TEMPLATE, "r", encoding="utf-8") as f:
            conf = f.read()
        for key, value in {
            "PORT": os.environ.get("PORT", "8080"),
            "NGINX_RUN_DIR": NGINX_RUN_DIR,
            "VLESS_WS_PATH": VLESS_WS_PATH, "VMESS_WS_PATH": VMESS_WS_PATH,
            "TROJAN_WS_PATH": TROJAN_WS_PATH, "HTTPUPGRADE_PATH": HTTPUPGRADE_PATH,
            "XHTTP_PATH": XHTTP_PATH,
        }.items():
            conf = conf.replace("${" + key + "}", value)
        with open(NGINX_CONF_OUT, "w", encoding="utf-8") as f:
            f.write(conf)
        res = subprocess.run(["nginx", "-e", "/dev/stderr", "-c", NGINX_CONF_OUT, "-s", "reload"], capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return False, "مسیر ذخیره شد ولی nginx ری‌لود نشد؛ یه بار سرویس رو Restart کن"
    except Exception:
        return False, "مسیر ذخیره شد ولی تنظیمات nginx به‌روز نشد؛ یه بار سرویس رو Restart کن"
    return True, ""


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


# آدرس‌های داخلی: جلوی اینکه کسی از طریق VPN به شبکه‌ی داخلی هاستینگ (یا خودِ سرور)
# دست بزنه گرفته می‌شه. عمداً CIDR صریح نوشتیم، نه geoip:private، چون فایل geoip.dat
# توی ایمیج نیست و Xray با اون قانون بالا نمیاد.
PRIVATE_CIDRS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
]


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
        # سه چیزی که بیشتر از همه باعث گزارش سوءاستفاده و بن‌شدن اکانت هاستینگ می‌شن:
        # تورنت، ارسال ایمیل (اسپم) و اسکن شبکه‌ی داخلی. هر سه مسدود می‌شن.
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
        {"type": "field", "port": "25,465,587", "outboundTag": "blocked"},
        {"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "blocked"},
    ]
    if domains:
        rules.append({
            "type": "field",
            "domain": sorted(set(domains)),
            "outboundTag": "blocked",
        })
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
    return rules


def build_config(data, level=0, xff=True):
    """level صفر یعنی همه‌ی ورودی‌ها؛ هرچی بالاتر بره، ورودی‌های تازه‌تر/بی‌ریسک‌تر
    کنار گذاشته می‌شن (فقط وقتی لازمه که نسخه‌ی Xray یکی‌شونو نشناسه):
    1 = بدون XHTTP، 2 = بدون XHTTP و HTTPUpgrade، 3 = فقط VLESS-WS و REALITY."""
    settings = data["settings"]
    clients_ws = []
    clients_reality = []
    clients_trojan = []
    for user in data["users"]:
        if user.get("is_active", True):
            clients_ws.append({"id": user["uuid"], "email": user["username"]})
            clients_trojan.append({"password": user["uuid"], "email": user["username"]})
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

    if level < 3:
        inbounds.append({
            "tag": "vmess-ws",
            "listen": "127.0.0.1",
            "port": VMESS_PORT,
            "protocol": "vmess",
            "settings": {"clients": list(clients_ws)},
            "streamSettings": {"network": "ws", "wsSettings": {"path": VMESS_WS_PATH}},
        })
        inbounds.append({
            "tag": "trojan-ws",
            "listen": "127.0.0.1",
            "port": TROJAN_PORT,
            "protocol": "trojan",
            "settings": {"clients": clients_trojan},
            "streamSettings": {"network": "ws", "wsSettings": {"path": TROJAN_WS_PATH}},
        })
    if level < 2:
        inbounds.append({
            "tag": "vless-httpupgrade",
            "listen": "127.0.0.1",
            "port": HTTPUPGRADE_PORT,
            "protocol": "vless",
            "settings": {"clients": list(clients_ws), "decryption": "none"},
            "streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": HTTPUPGRADE_PATH}},
        })
    if level < 1:
        inbounds.append({
            "tag": "vless-xhttp",
            "listen": "127.0.0.1",
            "port": XHTTP_PORT,
            "protocol": "vless",
            "settings": {"clients": list(clients_ws), "decryption": "none"},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": XHTTP_PATH, "mode": "auto"}},
        })

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

    # آی‌پی واقعی کاربر (برای شمارش دستگاه): پشت nginx/ریلوی، آی‌پی اتصال همیشه
    # لوکاله؛ پس از هدر ارسالی ریلوی خونده می‌شه. فقط برای ورودی‌های HTTP-محور.
    if xff:
        for ib in inbounds:
            ss = ib.get("streamSettings") or {}
            if ss.get("network") in ("ws", "httpupgrade", "xhttp"):
                ss["sockopt"] = {"trustedXForwardedFor": ["X-Real-IP", "X-Forwarded-For"]}

    # تشخیص نوع ترافیک (فقط برای قوانین مسدودسازی بالا؛ routeOnly یعنی مقصد واقعی
    # عوض نمی‌شه و به REALITY و بقیه آسیبی نمی‌زنه)
    for ib in inbounds:
        if ib["tag"] != "api":
            ib["sniffing"] = {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}

    config = {
        "log": {"loglevel": "warning", "access": ACCESS_LOG_PATH},
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


LAST_TEST_LOG = []   # خطای تست Xray برای هر سطح (برای عیب‌یابی در پنل)


def xray_version():
    try:
        res = subprocess.run([XRAY_BIN, "version"], capture_output=True, text=True, timeout=10)
        return (res.stdout or res.stderr or "").strip().splitlines()[0][:120]
    except Exception as e:
        return f"نامشخص ({type(e).__name__})"


def _xray_accepts(path):
    """True/False: آیا باینری Xray این فایل کانفیگ رو می‌پذیره؟ None یعنی نتونستیم
    تست کنیم (مثلاً باینری Xray روی این سیستم نیست)."""
    try:
        res = subprocess.run([XRAY_BIN, "run", "-test", "-format", "json", "-config", path],
                             capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            LAST_TEST_LOG.append(((res.stdout or "") + (res.stderr or "")).strip()[-400:])
        return res.returncode == 0
    except Exception:
        return None


def write_config(data):
    os.makedirs(os.path.dirname(XRAY_CONFIG_PATH), exist_ok=True)
    # قبل از نوشتن کانفیگ جدید، از کانفیگ فعلی (که تا الان کار می‌کرده) یه نسخه‌ی
    # پشتیبان نگه می‌داریم. اگه کانفیگ جدید به هر دلیلی (مثلاً یه دامنه‌ی عجیب)
    # خراب از آب دربیاد، می‌تونیم همینو برگردونیم تا کل پنل قطع نشه.
    if os.path.exists(XRAY_CONFIG_PATH):
        try:
            shutil.copyfile(XRAY_CONFIG_PATH, XRAY_CONFIG_PATH + ".bak")
        except Exception:
            pass

    # کانفیگ کامل رو اول تست می‌کنیم؛ اگه نسخه‌ی Xray یکی از ورودی‌های جدید (مثل
    # XHTTP) رو نشناخت، به‌جای اینکه کل VPN بخوابه، همون ورودی‌ها رو کنار می‌ذاریم
    # و با بقیه بالا میایم.
    tmp_path = os.path.splitext(XRAY_CONFIG_PATH)[0] + ".test.json"   # پسوند باید .json باشه تا Xray فرمتش رو بشناسه
    chosen, level_used = None, 3
    del LAST_TEST_LOG[:]
    global XFF_ACTIVE
    XFF_ACTIVE = False
    done = False
    for level in (0, 1, 2, 3):
        # اول با خوندن آی‌پی واقعی؛ اگه این Xray نشناخت، بدونش (ولی همه‌ی ورودی‌ها حفظ می‌شن)
        for xff in (True, False):
            config = build_config(data, level, xff)
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            ok = _xray_accepts(tmp_path)
            chosen, level_used = config, level
            if ok is None or ok:
                XFF_ACTIVE = xff
                done = True
                break
        if done:
            break
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(chosen, f, ensure_ascii=False, indent=2)
    global ACTIVE_LEVEL
    ACTIVE_LEVEL = level_used
    return chosen


XFF_ACTIVE = False   # آیا Xray آی‌پی واقعی کاربر رو از هدر می‌خونه؟


# چه سطحی از ورودی‌ها واقعاً فعال شد (برای اینکه لینک ورودی‌های غیرفعال ساخته نشه)
ACTIVE_LEVEL = 0


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
