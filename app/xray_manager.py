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
import subprocess
import time

from . import db

XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG_PATH = os.environ.get("XRAY_CONFIG_PATH", "/app/xray/config.json")
VLESS_WS_PATH = os.environ.get("VLESS_WS_PATH", "/vless-ws")
VLESS_PORT = int(os.environ.get("XRAY_VLESS_PORT", "10000"))
API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))

_xray_process = None


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
        line = line.strip()
        if line:
            domains.append(line)

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
    clients = []
    for user in data["users"]:
        if user.get("is_active", True):
            clients.append({"id": user["uuid"], "email": user["username"]})

    config = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": False, "statsInboundDownlink": False},
        },
        "inbounds": [
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
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": VLESS_WS_PATH},
                },
            },
        ],
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
    برای یه پنل کوچیک، ری‌استارت چند صدم‌ثانیه‌ای Xray کاملاً قابل قبوله."""
    write_config(data)
    stop_xray()
    time.sleep(0.3)
    start_xray()


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
    """مصرف همه‌ی کاربرها رو از Xray می‌گیره و توی دیتابیس آپدیت می‌کنه."""
    for user in data["users"]:
        used = query_traffic(user["username"])
        if used:
            user["used_traffic_bytes"] = used
    return data
