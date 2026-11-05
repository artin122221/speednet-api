"""شمارش دستگاه‌های هم‌زمان هر کاربر از روی لاگ دسترسی Xray.

هر خطِ لاگ یه اتصال رو نشون می‌ده: آی‌پیِ مبدأ + ایمیلِ (نام‌کاربری) کاربر.
تعداد آی‌پی‌های متفاوت توی ۵ دقیقه‌ی اخیر = تعداد دستگاه‌ها.
فقط وقتی کاربر دو بار پشت‌سرهم از حد بیشتر باشه قطع می‌شه (تا یه اتصال گذرا
قطعش نکنه)."""
import ipaddress
import os
import re
import threading
import time

ACCESS_LOG_PATH = os.environ.get("XRAY_ACCESS_LOG", "/tmp/xray-access.log")
WINDOW_SECONDS = 300
STRIKES_NEEDED = 2

_LINE_RE = re.compile(
    r"from\s+(?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9]+(?:\.[0-9]+){3}):\d+\s+accepted\s.*?email:\s*(\S+)"
)

_lock = threading.Lock()
_seen = {}      # username -> {ip: last_seen_ts}
_strikes = {}   # username -> تعداد بررسیِ پشت‌سرهمِ بالاتر از حد
_public_seen_at = 0.0   # آخرین باری که یه آی‌پی عمومی (واقعی) دیدیم
_events = []            # (username, ip, ts) هنوز توی دیتابیس ثبت نشده


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified)


def parse_line(line):
    """(ip, username) یا None."""
    m = _LINE_RE.search(line)
    if not m:
        return None
    ip = m.group(1).strip("[]")
    return ip, m.group(2)


def ingest(now=None):
    """خطوط جدید لاگ رو می‌خونه، توی حافظه ثبت می‌کنه و فایل رو خالی می‌کنه
    (تا لاگ بی‌نهایت بزرگ نشه). برمی‌گردونه چند خط جدید خونده شد."""
    global _public_seen_at
    now = now or time.time()
    try:
        with open(ACCESS_LOG_PATH, "r+", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
            f.seek(0)
            f.truncate()
    except OSError:
        return 0
    n = 0
    with _lock:
        for line in lines:
            p = parse_line(line)
            if not p:
                continue
            ip, user = p
            if not _is_public(ip):
                continue   # آی‌پی داخلی (nginx/پروکسی) رو نمی‌شمریم
            _seen.setdefault(user, {})[ip] = now
            if len(_events) < 5000:
                _events.append((user, ip, now))
            _public_seen_at = now
            n += 1
    return n


def real_ip_seen(max_age=3600):
    """آیا تو این یه ساعت اخیر حداقل یه آی‌پی واقعی دیدیم؟"""
    return (time.time() - _public_seen_at) <= max_age


def active_ips(username, now=None):
    now = now or time.time()
    with _lock:
        d = _seen.get(username, {})
        for ip in [i for i, t in d.items() if now - t > WINDOW_SECONDS]:
            del d[ip]
        return sorted(d.keys())


def count(username, now=None):
    return len(active_ips(username, now))


def forget(username):
    with _lock:
        _seen.pop(username, None)
        _strikes.pop(username, None)


def check_user(username, limit, now=None):
    """True اگه کاربر باید قطع بشه (دو بار پشت‌سرهم بیشتر از حد)."""
    if not limit or limit <= 0:
        _strikes.pop(username, None)
        return False
    if count(username, now) > limit:
        _strikes[username] = _strikes.get(username, 0) + 1
    else:
        _strikes[username] = 0
    return _strikes.get(username, 0) >= STRIKES_NEEDED


def drain_events():
    """رویدادهای جدید اتصال رو برمی‌گردونه و بافر رو خالی می‌کنه."""
    with _lock:
        ev = list(_events)
        del _events[:]
    return ev
