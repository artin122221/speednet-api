"""
ساخت صفحه‌ی اشتراکی که کاربر وقتی لینک ساب رو توی مرورگر باز می‌کنه می‌بینه.
دو طرح داریم (ادمین اصلی از «پنل شخصی» یکیشو انتخاب می‌کنه و برای همه‌ی
کاربرها اعمال می‌شه):
  - quantum: طرح جدید (پیش‌فرض)
  - classic: طرح قبلی
این فایل هیچ وابستگی‌ای به FastAPI نداره، پس مستقل هم قابل تست و پیش‌نمایشه.
"""
import base64
import html
import os
import re
from datetime import datetime, timezone

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

THEMES = {
    "quantum": "sub_quantum.html",
    "classic": "sub.html",
}
DEFAULT_THEME = "quantum"
# آیدی پشتیبانی صفحه‌ی ساب ثابته و از تنظیمات خونده نمی‌شه
_SUPPORT_ID = base64.b64decode("Q29uZmlnX3YycmV5X2ly").decode()
GB = 1024 ** 3


def normalize_theme(value):
    return value if value in THEMES else DEFAULT_THEME


def clean_telegram_id(value, default="Config_v2rey_ir"):
    """هر چی ادمین وارد کرده (@id یا t.me/id یا لینک کامل یا با فاصله) رو به آیدی خالی تبدیل می‌کنه."""
    v = (value or "").strip()
    v = re.sub(r"^(https?://)?(www\.)?(t\.me|telegram\.me)/", "", v, flags=re.I)
    v = v.lstrip("@").split("?")[0].strip("/ ")
    v = re.sub(r"[^A-Za-z0-9_]", "", v)
    return v or default


def _days_left(expire_at):
    """None یعنی بدون انقضا؛ عدد منفی یعنی منقضی شده؛ 'bad' یعنی تاریخ خراب."""
    if not expire_at:
        return None
    try:
        dt = datetime.fromisoformat(expire_at)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return "bad"


def render_sub_page(user, settings, sub_url, theme=None):
    theme = normalize_theme(theme or settings.get("sub_theme"))
    _b = settings.get("brand_name")
    brand = html.escape(_b if _b and _b != "Speed Panel" else "Speed X4G")
    support = html.escape(_SUPPORT_ID)
    link = html.escape(sub_url, quote=True)

    limit_bytes = user.get("data_limit_bytes") or 0
    used_bytes = user.get("used_traffic_bytes") or 0
    used_gb = used_bytes / GB
    limit_gb = limit_bytes / GB
    percent = 0 if not limit_bytes else max(0, min(100, (used_bytes / limit_bytes) * 100))

    days = _days_left(user.get("expire_at"))
    is_active = user.get("is_active", True)

    with open(os.path.join(STATIC_DIR, THEMES[theme]), "r", encoding="utf-8") as f:
        page = f.read()

    if theme == "quantum":
        if days is None:
            validity = "∞ <small>no expiry</small>"
        elif days == "bad":
            validity = "— <small>unknown</small>"
        elif days < 0:
            validity = "0 <small>expired</small>"
        else:
            validity = f"{days} <small>days left</small>"
        if limit_bytes:
            total = f'{used_gb:.1f} GB <span class="dim">/ {limit_gb:.1f} GB</span>'
        else:
            total = f'{used_gb:.1f} GB <span class="dim">/ Unlimited</span>'
        # اسم برند رو برای تیتر بزرگ بین کلمه‌ی اول و بقیه می‌شکنیم
        parts = brand.split(" ", 1)
        brand_h1 = parts[0] + ("<br>" + parts[1] if len(parts) > 1 else "")
        replacements = {
            "__BRAND_H1__": brand_h1,
            "__BRAND__": brand,
            "__SUPPORT_TELEGRAM__": support,
            "__SUB_LINK__": link,
            "__USED_HTML__": f"{used_gb:.1f} <small>GB used</small>",
            "__VALIDITY_HTML__": validity,
            "__TOTAL_HTML__": total,
            "__TRAFFIC_PERCENT__": f"{percent:.0f}",
            "__STATUS_TEXT__": "SERVICE ACTIVE" if is_active else "SERVICE PAUSED",
            "__LIVE_TEXT__": "ALL SYSTEMS GO" if is_active else "ACCOUNT PAUSED",
            "__STATUS_CLASS__": "" if is_active else "off",
        }
    else:
        if not limit_bytes:
            traffic_html = f"{used_gb:.1f} <small>GB (UNLIMITED)</small>"
        else:
            traffic_html = f"{used_gb:.1f} <small>GB / {limit_gb:.1f} GB</small>"
        if days is None:
            time_html = "∞ <small>UNLIMITED</small>"
        elif days == "bad":
            time_html = "— <small>—</small>"
        elif days < 0:
            time_html = "EXPIRED <small>—</small>"
        else:
            time_html = f"{days} <small>DAYS</small>"
        replacements = {
            "__BRAND__": brand,
            "__SUPPORT_TELEGRAM__": support,
            "__SUB_LINK__": link,
            "__TRAFFIC_VALUE_HTML__": traffic_html,
            "__TRAFFIC_PERCENT__": f"{percent:.0f}",
            "__TIME_VALUE_HTML__": time_html,
            "__STATUS_TEXT__": "ACTIVE" if is_active else "INACTIVE",
            "__STATUS_EXTRA_CLASS__": "" if is_active else "inactive",
        }

    # طولانی‌ترین کلید اول، تا __BRAND_H1__ قبل از __BRAND__ جایگزین بشه
    for key in sorted(replacements, key=len, reverse=True):
        page = page.replace(key, replacements[key])
    return page
