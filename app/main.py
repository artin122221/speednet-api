import base64
import io
import math
import os
import platform
import secrets
import threading
import time
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import bcrypt
import httpx
import psutil
import qrcode
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import db, xray_manager

APP_VERSION = "1.0"
START_TIME = time.time()
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

# اختیاریه: اگه می‌خوای این پنل به سرور آپدیت مرکزی خودت (پروژه‌ی جدای
# license-server) معرفی بشه و خبر آپدیت جدید رو خودکار بگیره، فقط همین یکی
# رو توی Variables ریلوی تنظیم کن. چیز دیگه‌ای لازم نیست.
# UPDATE_SERVER_URL = آدرس همون سرور آپدیت مرکزی‌ت
UPDATE_SERVER_URL = os.environ.get("UPDATE_SERVER_URL", "").rstrip("/")

app = FastAPI(title="Speed Panel API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== ابزارهای کمکی ====================

def get_db():
    return db.load()


def save_db(data):
    db.save(data)


def ensure_admin_password(data):
    """اولین باری که سرور بالا میاد، اگه رمزی تنظیم نشده، رمز پیش‌فرض admin رو می‌سازه."""
    if not data["settings"].get("admin_password_hash"):
        data["settings"]["admin_password_hash"] = hash_password("admin")
        save_db(data)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def require_admin(authorization: str | None):
    data = get_db()
    ensure_admin_password(data)
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
    active = data["settings"].get("active_token")
    if not token or not active or token != active:
        raise HTTPException(status_code=401, detail="نشست شما منقضی شده، دوباره وارد شوید")
    return data


def build_vless_link(user, request_host: str):
    """لینک واقعی VLESS که با دامنه‌ی ریلوی و روی TLS/WebSocket کار می‌کنه."""
    uuid_ = user["uuid"]
    path = xray_manager.VLESS_WS_PATH
    remark = f"SpeedPanel-{user['username']}"
    return (
        f"vless://{uuid_}@{request_host}:443"
        f"?encryption=none&security=tls&type=ws&host={request_host}&path={path}&sni={request_host}"
        f"#{remark}"
    )


def build_vless_reality_link(user, settings):
    """لینک VLESS+REALITY؛ فقط وقتی ساخته می‌شه که ادمین آدرس و پورت
    TCP Proxy ریلوی رو توی تنظیمات وارد کرده باشه. ترافیکش شبیه یه سایت واقعی
    به نظر می‌رسه و تشخیصش برای فیلترها/ضدسوءاستفاده سخت‌تره."""
    host = settings.get("reality_external_host")
    port = settings.get("reality_external_port")
    public_key = settings.get("reality_public_key")
    short_id = settings.get("reality_short_id")
    if not (host and port and public_key):
        return None
    uuid_ = user["uuid"]
    remark = f"SpeedPanel-Reality-{user['username']}"
    return (
        f"vless://{uuid_}@{host}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={xray_manager.REALITY_SERVER_NAME}&fp=chrome&pbk={public_key}&sid={short_id or ''}&type=tcp"
        f"#{remark}"
    )


# ==================== مدل‌های ورودی ====================

class LoginBody(BaseModel):
    username: str
    password: str


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


class CreateUserBody(BaseModel):
    username: str
    data_limit_gb: float = 0
    days_valid: int = 0
    device_limit: int = 2
    speed_limit_mbps: int | None = None


class UpdateUserBody(BaseModel):
    data_limit_gb: float | None = None
    days_valid: int | None = None
    device_limit: int | None = None
    speed_limit_mbps: int | None = None
    reset_usage: bool = False


class SettingsBody(BaseModel):
    brand_name: str | None = None
    support_telegram: str | None = None
    server_region: str | None = None
    server_host_name: str | None = None
    latest_version: str | None = None
    update_message: str | None = None
    reality_external_host: str | None = None
    reality_external_port: str | None = None


class BlockingBody(BaseModel):
    services: list[str] = []
    domains: str = ""


class TelegramConnectBody(BaseModel):
    token: str


class PlanBody(BaseModel):
    name: str
    price_toman: int
    data_limit_gb: float = 0
    days_valid: int = 0
    device_limit: int = 2


class ShopSettingsBody(BaseModel):
    card_number: str | None = None
    card_holder: str | None = None
    welcome_message: str | None = None


class RestoreBody(BaseModel):
    users: list
    settings: dict | None = None
    restore_settings: bool = False


# ==================== وضعیت عمومی (بدون نیاز به ورود) ====================

def check_update_server(data, request_host: str):
    """اگه UPDATE_SERVER_URL تنظیم شده باشه، این پنل خودش رو (با یه شناسه‌ی
    یکتا) به سرور آپدیت مرکزی معرفی می‌کنه و می‌پرسه نسخه‌ی جدیدی اومده یا نه.
    کاملاً رایگان و بدون قفل — فقط یه اطلاع‌رسانیه."""
    if not UPDATE_SERVER_URL:
        return None
    try:
        res = httpx.get(
            f"{UPDATE_SERVER_URL}/check",
            params={"instance_id": data["instance_id"], "version": APP_VERSION, "domain": request_host},
            timeout=5,
        )
        return res.json()
    except Exception:
        return None


@app.get("/status")
def status():
    data = get_db()
    ensure_admin_password(data)
    settings = data["settings"]

    update_info = check_update_server(data, data["settings"].get("server_host_name", ""))
    if update_info is not None:
        # منبع حقیقت آپدیت، سرور مرکزی آپدیته (همونی که خودت اداره می‌کنی)
        update_available = update_info.get("update_available", False)
        latest_version = update_info.get("latest_version")
        changelog = update_info.get("changelog")
        download_url = update_info.get("download_url")
    else:
        # حالت ساده‌ی قبلی: خودت از داخل «پنل شخصی» نسخه رو دستی اعلام می‌کنی
        update_available = bool(settings.get("latest_version")) and settings["latest_version"] != APP_VERSION
        latest_version = settings.get("latest_version")
        changelog = settings.get("update_message", "")
        download_url = None

    return {
        "host": settings.get("server_host_name", "Railway"),
        "region": settings.get("server_region", ""),
        "version": APP_VERSION,
        "latest_version": latest_version,
        "update_available": update_available,
        "update_changelog": changelog,
        "update_download_url": download_url,
        "update_message": settings.get("update_message", ""),
        "brand_name": settings.get("brand_name", "Speed Panel"),
        "support_telegram": settings.get("support_telegram", ""),
    }


@app.get("/panel", response_class=HTMLResponse)
def panel():
    return FileResponse(os.path.join(STATIC_DIR, "panel.html"))


@app.get("/")
def root():
    return FileResponse(os.path.join(STATIC_DIR, "panel.html"))


# ==================== ورود ====================

@app.post("/admin/login")
def login(body: LoginBody):
    data = get_db()
    ensure_admin_password(data)
    if body.username != "admin" or not check_password(body.password, data["settings"]["admin_password_hash"]):
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = secrets.token_hex(32)
    data["settings"]["active_token"] = token
    save_db(data)
    return {"token": token}


@app.post("/admin/change-password")
def change_password(body: ChangePasswordBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    if not check_password(body.current_password, data["settings"]["admin_password_hash"]):
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    if len(body.new_password) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    data["settings"]["admin_password_hash"] = hash_password(body.new_password)
    data["settings"]["active_token"] = None  # اجبار به ورود دوباره
    save_db(data)
    return {"ok": True}


# ==================== کاربران ====================

@app.get("/users")
def list_users(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    xray_manager.refresh_all_traffic(data)
    changed = xray_manager.enforce_limits(data)
    save_db(data)
    if changed:
        try:
            xray_manager.apply_and_restart(data)
        except RuntimeError:
            pass
    return data["users"]


def _create_user_internal(data, username, data_limit_gb=0, days_valid=0, device_limit=2, speed_limit_mbps=None):
    """هسته‌ی ساخت کاربر؛ هم از API معمولی (فرم توی پنل) و هم از دستور ربات
    تلگرام صدا زده می‌شه، که منطق ساخت کاربر یه‌جا بمونه. برمی‌گردونه:
    (user_dict یا None، پیام‌خطا یا None). اگه apply_and_restart شکست بخوره،
    کاربر همچنان ساخته و ذخیره شده، ولی پیام‌خطا هم برمی‌گرده."""
    username = (username or "").strip()
    if not username:
        return None, "نام کاربری نمی‌تواند خالی باشد"
    if any(u["username"] == username for u in data["users"]):
        return None, "این نام کاربری قبلاً ساخته شده"

    expire_at = None
    if days_valid and days_valid > 0:
        expire_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()

    user = {
        "username": username,
        "uuid": str(uuidlib.uuid4()),
        "subscription_token": secrets.token_urlsafe(16),
        "data_limit_bytes": int(data_limit_gb * (1024 ** 3)) if data_limit_gb else 0,
        "used_traffic_bytes": 0,
        "traffic_baseline_bytes": 0,
        "device_limit": device_limit,
        "speed_limit_mbps": speed_limit_mbps,
        "expire_at": expire_at,
        "created_at": db.now_iso(),
        "is_active": True,
        "last_seen_at": None,
        "_last_session_bytes": 0,
    }
    data["users"].append(user)
    save_db(data)
    try:
        xray_manager.apply_and_restart(data)
    except RuntimeError as e:
        return user, str(e)
    return user, None


@app.post("/users")
def create_user(body: CreateUserBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    user, err = _create_user_internal(
        data, body.username, body.data_limit_gb, body.days_valid, body.device_limit, body.speed_limit_mbps
    )
    if user is None:
        raise HTTPException(status_code=400, detail=err)
    if err:
        raise HTTPException(status_code=400, detail=err)
    return user


def _apply_and_restart_safe(data):
    """صدا زدن apply_and_restart، ولی اگه کانفیگ جدید باعث کرش Xray بشه، به‌جای
    اینکه کل درخواست با یه خطای ناشناخته (که توی مرورگر چیزی شبیه Failed to
    fetch نشون می‌ده) بترکه، یه پیام فارسی روشن برمی‌گردونیم."""
    try:
        xray_manager.apply_and_restart(data)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.patch("/users/{username}/toggle")
def toggle_user(username: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    for u in data["users"]:
        if u["username"] == username:
            u["is_active"] = not u["is_active"]
            save_db(data)
            _apply_and_restart_safe(data)
            return {"ok": True, "is_active": u["is_active"]}
    raise HTTPException(status_code=404, detail="کاربر پیدا نشد")


@app.patch("/users/{username}")
def update_user(username: str, body: UpdateUserBody, authorization: str | None = Header(default=None)):
    """ویرایش یه کاربر موجود: حجم، مدت اعتبار، تعداد دستگاه و محدودیت سرعت."""
    data = require_admin(authorization)
    user = next((u for u in data["users"] if u["username"] == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")

    if body.data_limit_gb is not None:
        user["data_limit_bytes"] = int(body.data_limit_gb * (1024 ** 3)) if body.data_limit_gb else 0
    if body.days_valid is not None:
        if body.days_valid > 0:
            user["expire_at"] = (datetime.now(timezone.utc) + timedelta(days=body.days_valid)).isoformat()
        else:
            user["expire_at"] = None
    if body.device_limit is not None:
        user["device_limit"] = body.device_limit
    if "speed_limit_mbps" in body.model_fields_set:
        user["speed_limit_mbps"] = body.speed_limit_mbps
    if body.reset_usage:
        user["used_traffic_bytes"] = 0
        user["traffic_baseline_bytes"] = 0

    save_db(data)
    _apply_and_restart_safe(data)
    return user


@app.delete("/users/{username}")
def delete_user(username: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u["username"] != username]
    if len(data["users"]) == before:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
    save_db(data)
    _apply_and_restart_safe(data)
    return {"ok": True}


# ==================== لینک اشتراک ====================
# اگه اپ VPN (v2rayNG, Hiddify, ...) این لینک رو باز کنه، باید متن ساده‌ی
# base64 بگیره. اگه خودِ کاربر توی مرورگر بازش کنه، یه صفحه‌ی خوشگل با QR
# کد، دکمه‌ی کپی، و کانال‌های تلگرام می‌بینه. تشخیص از روی User-Agent انجام
# می‌شه چون همه‌ی این اپ‌ها یه الگوی مشخص توی User-Agent خودشون دارن.
VPN_APP_USER_AGENTS = (
    "v2ray", "v2box", "hiddify", "streisand", "shadowrocket", "nekoray",
    "neko", "singbox", "sing-box", "clash", "stash", "quantumult",
    "surge", "karing", "husi", "foxray", "v2rayng", "v2rayn", "matsuri",
)


def is_vpn_app(user_agent: str | None) -> bool:
    if not user_agent:
        return False
    ua = user_agent.lower()
    return any(tag in ua for tag in VPN_APP_USER_AGENTS)


def format_bytes_gb(num_bytes):
    if not num_bytes:
        return "نامحدود"
    return f"{num_bytes / (1024 ** 3):.1f} GB"


def format_used_gb(used_bytes):
    return f"{(used_bytes or 0) / (1024 ** 3):.1f} GB"


def _build_qr_data_uri(link: str) -> str:
    """کیوآر کد رو همین‌جا توی سرور می‌سازیم (نه با جاوااسکریپت توی مرورگر از
    روی یه CDN خارجی)، چون خیلی از کاربرها قبل از وصل شدن به VPN اصلاً نمی‌تونن
    به سرورهای خارج از ایران وصل بشن و در نتیجه کیوآر کد هیچ‌وقت ساخته نمی‌شد."""
    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def format_expire(expire_at):
    if not expire_at:
        return "بدون انقضا"
    try:
        dt = datetime.fromisoformat(expire_at)
        days_left = (dt - datetime.now(timezone.utc)).days
        return f"{days_left} روز مانده" if days_left >= 0 else "منقضی شده"
    except Exception:
        return "—"


def format_last_seen(last_seen_at):
    """نمایش «آخرین اتصال» به‌صورت نسبی. دقتش حدود ۲ دقیقه‌ست (فاصله‌ی چک
    خودکار پنل)، پس برای همین کار کاملاً کافیه."""
    if not last_seen_at:
        return "هنوز وصل نشده"
    try:
        dt = datetime.fromisoformat(last_seen_at)
        secs = (datetime.now(timezone.utc) - dt).total_seconds()
        if secs < 150:
            return "همین الان"
        if secs < 3600:
            return f"{int(secs // 60)} دقیقه پیش"
        if secs < 86400:
            return f"{int(secs // 3600)} ساعت پیش"
        return f"{int(secs // 86400)} روز پیش"
    except Exception:
        return "—"


def _esc_attr(value: str) -> str:
    """برای امن قرار دادن یه مقدار داخل attribute هوشمند HTML (مثل data-link)."""
    return (value or "").replace("&", "&amp;").replace('"', "&quot;")


def _config_row_html(name: str, badge: str, link: str, qr_data_uri: str) -> str:
    return f"""
    <div class="config-row" data-qr="{qr_data_uri}">
      <button type="button" class="icon-btn" onclick="showQr(this)" title="نمایش QR">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="3" height="3"/><rect x="18" y="18" width="3" height="3"/><rect x="14" y="18" width="3" height="3"/><rect x="18" y="14" width="3" height="3"/></svg>
      </button>
      <button type="button" class="icon-btn" onclick="copyCfg(this)" data-link="{_esc_attr(link)}" title="کپی">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>
      </button>
      <span class="config-name">{name}</span>
      <span class="badge">{badge}</span>
    </div>"""


def build_config_rows_html(sub_url, ws_link, reality_link, primary_link, qr_sub, qr_ws, qr_reality):
    rows = []
    rows.append(_config_row_html("لینک اشتراک", "SUB", sub_url, qr_sub))
    if reality_link:
        rows.append(_config_row_html("کانفیگ اصلی", "REALITY", reality_link, qr_reality))
        if ws_link and ws_link != reality_link:
            rows.append(_config_row_html("کانفیگ پشتیبان", "VLESS", ws_link, qr_ws))
    else:
        rows.append(_config_row_html("کانفیگ اصلی", "VLESS", ws_link, qr_ws))
    return "".join(rows)


@app.get("/sub/{token}")
def subscription(
    token: str,
    host: str | None = Header(default=None, alias="host"),
    user_agent: str | None = Header(default=None, alias="user-agent"),
):
    data = get_db()
    user = next((u for u in data["users"] if u["subscription_token"] == token), None)
    if not user:
        raise HTTPException(status_code=404, detail="یافت نشد")
    xray_manager.refresh_all_traffic(data)
    save_db(data)
    domain = host or data["settings"].get("railway_domain") or "localhost"
    ws_link = build_vless_link(user, domain)
    reality_link = build_vless_reality_link(user, data["settings"])
    # اگه REALITY تنظیم شده باشه (آدرس/پورت TCP Proxy وارد شده)، همونو به‌عنوان
    # لینک اصلی می‌دیم چون تشخیصش سخت‌تره؛ وگرنه همون VLESS+WS قبلی رو می‌دیم.
    primary_link = reality_link or ws_link

    if is_vpn_app(user_agent):
        links = [primary_link]
        if reality_link and ws_link != primary_link:
            links.append(ws_link)
        content = "\n".join(links)
        return PlainTextResponse(base64.b64encode(content.encode("utf-8")).decode("utf-8"))

    sub_url = f"https://{domain}/sub/{token}"
    limit_bytes = user.get("data_limit_bytes") or 0
    used_bytes = user.get("used_traffic_bytes") or 0
    if not limit_bytes:
        percent = 0
        traffic_html = f"{used_bytes / (1024 ** 3):.1f} <small>GB (UNLIMITED)</small>"
    else:
        percent = max(0, min(100, (used_bytes / limit_bytes) * 100))
        traffic_html = f"{used_bytes / (1024 ** 3):.1f} <small>GB / {limit_bytes / (1024 ** 3):.1f} GB</small>"

    expire_at = user.get("expire_at")
    if not expire_at:
        time_html = "∞ <small>UNLIMITED</small>"
    else:
        try:
            dt = datetime.fromisoformat(expire_at)
            days_left = (dt - datetime.now(timezone.utc)).days
            time_html = f"{days_left} <small>DAYS</small>" if days_left >= 0 else "EXPIRED <small>—</small>"
        except Exception:
            time_html = "— <small>—</small>"

    is_active = user.get("is_active", True)
    status_text = "ACTIVE" if is_active else "INACTIVE"
    status_extra_class = "" if is_active else "inactive"

    with open(os.path.join(STATIC_DIR, "sub.html"), "r", encoding="utf-8") as f:
        page = f.read()
    page = (
        page.replace("__BRAND__", data["settings"].get("brand_name") or "Speed Panel")
            .replace("__SUPPORT_TELEGRAM__", data["settings"].get("support_telegram") or "Config_v2rey_ir")
            .replace("__SUB_LINK__", sub_url)
            .replace("__TRAFFIC_VALUE_HTML__", traffic_html)
            .replace("__TRAFFIC_PERCENT__", f"{percent:.0f}")
            .replace("__TIME_VALUE_HTML__", time_html)
            .replace("__STATUS_TEXT__", status_text)
            .replace("__STATUS_EXTRA_CLASS__", status_extra_class)
    )
    return HTMLResponse(page)


# ==================== پنل شخصی / تنظیمات ====================

@app.get("/admin/settings")
def get_settings(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    s = data["settings"]
    return {
        "brand_name": s.get("brand_name"),
        "support_telegram": s.get("support_telegram"),
        "server_region": s.get("server_region"),
        "server_host_name": s.get("server_host_name"),
        "latest_version": s.get("latest_version"),
        "update_message": s.get("update_message"),
        "blocked_domains": s.get("blocked_domains"),
        "blocked_services": s.get("blocked_services"),
        "service_catalog": db.DEFAULT_SERVICE_CATALOG,
        "telegram": s.get("telegram"),
        # کلید عمومی و شناسه‌ی کوتاه مشکلی نداره دیده بشن (داخل لینک کاربر هم
        # هست)، ولی کلید خصوصی هیچ‌وقت نباید از این مسیر برگرده.
        "reality_public_key": s.get("reality_public_key"),
        "reality_short_id": s.get("reality_short_id"),
        "reality_external_host": s.get("reality_external_host"),
        "reality_external_port": s.get("reality_external_port"),
    }


@app.put("/admin/settings")
def put_settings(body: SettingsBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    s = data["settings"]
    for field in ("brand_name", "support_telegram", "server_region", "server_host_name",
                  "latest_version", "update_message",
                  "reality_external_host", "reality_external_port"):
        value = getattr(body, field)
        if value is not None:
            s[field] = value
    save_db(data)
    return {"ok": True}


@app.put("/admin/telegram-shop")
def put_telegram_shop(body: ShopSettingsBody, authorization: str | None = Header(default=None)):
    """تنظیمات ربات فروش خودکار: شماره کارت، نام صاحب کارت، پیام خوش‌آمدگویی."""
    data = require_admin(authorization)
    telegram = data["settings"].setdefault("telegram", {})
    for field in ("card_number", "card_holder", "welcome_message"):
        value = getattr(body, field)
        if value is not None:
            telegram[field] = value
    save_db(data)
    return {"ok": True}


@app.get("/admin/plans")
def list_plans(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    return data.get("plans", [])


@app.post("/admin/plans")
def create_plan(body: PlanBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    plan = {
        "id": secrets.token_hex(4),
        "name": body.name.strip(),
        "price_toman": body.price_toman,
        "data_limit_gb": body.data_limit_gb,
        "days_valid": body.days_valid,
        "device_limit": body.device_limit,
    }
    if not plan["name"]:
        raise HTTPException(status_code=400, detail="نام تعرفه نمی‌تواند خالی باشد")
    data.setdefault("plans", []).append(plan)
    save_db(data)
    return plan


@app.delete("/admin/plans/{plan_id}")
def delete_plan(plan_id: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    data["plans"] = [p for p in data.get("plans", []) if p["id"] != plan_id]
    save_db(data)
    return {"ok": True}


@app.get("/admin/orders")
def list_orders(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    return list(reversed(data.get("orders", [])))


@app.put("/admin/blocking")
def put_blocking(body: BlockingBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    data["settings"]["blocked_services"] = body.services
    data["settings"]["blocked_domains"] = body.domains
    save_db(data)
    _apply_and_restart_safe(data)
    return {"ok": True}


@app.get("/admin/routing-rules")
def routing_rules(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    return {"rules": xray_manager.build_routing_rules(data["settings"])}


def _build_backup_payload(data):
    return {
        "format": "speedpanel-backup",
        "users": data["users"],
        "settings": {k: v for k, v in data["settings"].items()
                      if k not in ("admin_password_hash", "active_token")},
    }


@app.get("/admin/backup")
def backup(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    payload = _build_backup_payload(data)
    import json
    from fastapi.responses import Response
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=speedpanel-backup.json"},
    )


@app.post("/admin/restore")
def restore(body: RestoreBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    existing_usernames = {u["username"] for u in data["users"]}
    added, skipped = 0, 0
    for u in body.users:
        if u.get("username") in existing_usernames:
            skipped += 1
            continue
        u.setdefault("uuid", str(uuidlib.uuid4()))
        u.setdefault("subscription_token", secrets.token_urlsafe(16))
        u.setdefault("traffic_baseline_bytes", u.get("used_traffic_bytes", 0))
        data["users"].append(u)
        existing_usernames.add(u["username"])
        added += 1
    if body.restore_settings and body.settings:
        for k, v in body.settings.items():
            if k not in ("admin_password_hash", "active_token"):
                data["settings"][k] = v
    save_db(data)
    _apply_and_restart_safe(data)
    return {"ok": True, "added": added, "skipped": skipped}


@app.post("/admin/telegram/connect")
def telegram_connect(body: TelegramConnectBody, request: Request, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    try:
        res = httpx.get(f"https://api.telegram.org/bot{body.token}/getMe", timeout=10)
        info = res.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اتصال به تلگرام برقرار نشد")
    if not info.get("ok"):
        raise HTTPException(status_code=400, detail="توکن ربات نامعتبر است")
    username = info["result"]["username"]

    # این بخشیه که واقعاً ربات رو «زنده» می‌کنه: به تلگرام می‌گیم هر پیامی که
    # کاربرها برای ربات می‌فرستن رو مستقیم به همین دامنه (همون‌جایی که خودِ پنل
    # روشه) پاس بده. بدون این مرحله، توکن فقط ذخیره می‌شه ولی ربات به هیچ پیامی
    # جواب نمی‌ده.
    webhook_warning = None
    host = request.headers.get("host")
    if host:
        webhook_url = f"https://{host}/telegram/webhook/{body.token}"
        try:
            wh = httpx.get(
                f"https://api.telegram.org/bot{body.token}/setWebhook",
                params={"url": webhook_url},
                timeout=10,
            )
            if not wh.json().get("ok"):
                webhook_warning = "ربات وصل شد ولی وبهوکش تنظیم نشد؛ دوباره امتحان کن"
        except Exception:
            webhook_warning = "ربات وصل شد ولی ارتباط با تلگرام برای تنظیم وبهوک برقرار نشد"

    # admin_chat_id هنوز خالیه؛ اولین نفری که به ربات پیام بده (با /start) به‌عنوان
    # «مدیر» ثبت می‌شه و از اون به بعد فقط همون چت اجازه‌ی دستور داره. برای همینه
    # که ادمین باید بلافاصله بعد از وصل کردن، خودش بره تو تلگرام و به رباتش پیام بده.
    data["settings"]["telegram"] = {
        "connected": True, "token": body.token, "username": username, "admin_chat_id": None,
    }
    save_db(data)
    return {"ok": True, "username": username, "warning": webhook_warning}


@app.post("/admin/telegram/disconnect")
def telegram_disconnect(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    token = (data["settings"].get("telegram") or {}).get("token")
    if token:
        try:
            httpx.get(f"https://api.telegram.org/bot{token}/deleteWebhook", timeout=10)
        except Exception:
            pass
    data["settings"]["telegram"] = {"connected": False, "token": None, "username": None, "admin_chat_id": None}
    save_db(data)
    return {"ok": True}


def _telegram_send(token: str, chat_id, text: str):
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
    except Exception:
        pass


def _telegram_send_document(token: str, chat_id, filename: str, content_bytes: bytes, caption: str = ""):
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data={"chat_id": chat_id, "caption": caption},
            files={"document": (filename, content_bytes, "application/json")},
            timeout=30,
        )
    except Exception:
        pass


def _telegram_send_with_keyboard(token: str, chat_id, text: str, keyboard_rows):
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "reply_markup": {"inline_keyboard": keyboard_rows}},
            timeout=10,
        )
    except Exception:
        pass


def _telegram_send_photo_with_keyboard(token: str, chat_id, file_id: str, caption: str, keyboard_rows):
    """عکس رسید رو (بدون آپلود دوباره، فقط با file_id همونی که از مشتری گرفتیم)
    برای ادمین می‌فرسته، همراه با دکمه‌های تایید/رد."""
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendPhoto",
            json={"chat_id": chat_id, "photo": file_id, "caption": caption,
                  "reply_markup": {"inline_keyboard": keyboard_rows}},
            timeout=15,
        )
    except Exception:
        pass


def _telegram_answer_callback(token: str, callback_query_id: str, text: str = ""):
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id, "text": text},
            timeout=10,
        )
    except Exception:
        pass


TELEGRAM_HELP_TEXT = (
    "دستورهای ربات (فقط برای مدیر پنل):\n\n"
    "/newuser نام_کاربری حجم_گیگ مدت_روز تعداد_دستگاه\n"
    "مثال: /newuser ali 50 30 2\n"
    "(حجم، مدت و تعداد دستگاه اختیاری‌ان؛ پیش‌فرض: نامحدود، نامحدود، ۲)\n\n"
    "/backup\n"
    "گرفتن فایل بکاپ کامل (کاربرها + تنظیمات)\n\n"
    "/help\n"
    "نمایش همین راهنما\n\n"
    "هر مشتری دیگه‌ای که به ربات پیام بده، خودکار منوی خرید (تعرفه‌ها) رو "
    "می‌بینه و وقتی عکس رسید واریزی رو بفرسته، همینجا برات با دکمه‌ی تایید/رد "
    "فرستاده می‌شه."
)


def _find_plan(data, plan_id):
    return next((p for p in data.get("plans", []) if p["id"] == plan_id), None)


def _find_order(data, order_id):
    return next((o for o in data.get("orders", []) if o["id"] == order_id), None)


def _find_open_order_for_chat(data, chat_id):
    for order in reversed(data.get("orders", [])):
        if order["chat_id"] == chat_id and order["status"] == "awaiting_receipt":
            return order
    return None


def _handle_customer_message(token, data, telegram, message, chat_id, host):
    """پیامی که از یه چت غیرادمین (یعنی احتمالاً یه مشتری) رسیده."""
    text = (message.get("text") or "").strip()
    photo = message.get("photo")

    if photo:
        order = _find_open_order_for_chat(data, chat_id)
        if not order:
            _telegram_send(token, chat_id, "سفارش بازی برات پیدا نکردم. برای دیدن تعرفه‌ها /start رو بزن.")
            return
        order["receipt_file_id"] = photo[-1]["file_id"]
        order["status"] = "pending_review"
        save_db(data)
        _telegram_send(token, chat_id, "✅ رسیدت دریافت شد و برای بررسی برای مدیر فرستاده شد. منتظر تایید باش.")
        admin_chat_id = telegram.get("admin_chat_id")
        if admin_chat_id:
            caption = (
                "🧾 رسید پرداخت جدید\n"
                f"مشتری: {message.get('from', {}).get('first_name', '')} (chat_id: {chat_id})\n"
                f"تعرفه: {order['plan_name']} — {order['price_toman']:,} تومان\n"
                f"کد سفارش: {order['id']}"
            )
            keyboard = [[
                {"text": "✅ تایید و ساخت کانفیگ", "callback_data": f"ord_ok:{order['id']}"},
                {"text": "❌ رد کردن", "callback_data": f"ord_no:{order['id']}"},
            ]]
            _telegram_send_photo_with_keyboard(token, admin_chat_id, order["receipt_file_id"], caption, keyboard)
        return

    if not text or text.startswith("/start"):
        plans = data.get("plans", [])
        welcome = telegram.get("welcome_message") or "سلام! به ربات فروش خوش اومدی. یکی از تعرفه‌های زیر رو انتخاب کن:"
        if not plans:
            _telegram_send(token, chat_id, welcome + "\n\nفعلاً هیچ تعرفه‌ای تعریف نشده؛ یکم دیگه دوباره امتحان کن.")
            return
        keyboard = [
            [{"text": f"{p['name']} — {p['price_toman']:,} تومان", "callback_data": f"plan:{p['id']}"}]
            for p in plans
        ]
        _telegram_send_with_keyboard(token, chat_id, welcome, keyboard)
        return

    _telegram_send(token, chat_id, "برای دیدن تعرفه‌ها و خرید، دستور /start رو بزن.")


def _handle_telegram_callback(token, data, telegram, callback, admin_chat_id, host):
    """تلگرام وقتی کاربر رو یکی از دکمه‌های شیشه‌ای بزنه، یه callback_query
    می‌فرسته (نه یه پیام معمولی)."""
    cb_id = callback.get("id")
    cb_data = callback.get("data") or ""
    from_chat = (callback.get("message") or {}).get("chat", {}).get("id")
    if not from_chat:
        return

    if cb_data.startswith("plan:"):
        plan_id = cb_data.split(":", 1)[1]
        plan = _find_plan(data, plan_id)
        _telegram_answer_callback(token, cb_id)
        if not plan:
            _telegram_send(token, from_chat, "این تعرفه دیگه موجود نیست.")
            return
        order = {
            "id": secrets.token_hex(6),
            "chat_id": from_chat,
            "customer_name": callback.get("from", {}).get("first_name", ""),
            "plan_id": plan["id"],
            "plan_name": plan["name"],
            "price_toman": plan["price_toman"],
            "data_limit_gb": plan.get("data_limit_gb", 0),
            "days_valid": plan.get("days_valid", 0),
            "device_limit": plan.get("device_limit", 2),
            "status": "awaiting_receipt",
            "receipt_file_id": None,
            "created_at": db.now_iso(),
            "username": None,
        }
        data.setdefault("orders", []).append(order)
        save_db(data)
        card_number = telegram.get("card_number") or "— (ادمین هنوز شماره کارت وارد نکرده)"
        card_holder = telegram.get("card_holder") or "—"
        _telegram_send(
            token, from_chat,
            f"تعرفه‌ی «{plan['name']}» انتخاب شد.\n"
            f"مبلغ: {plan['price_toman']:,} تومان\n\n"
            f"لطفاً این مبلغ رو به شماره کارت زیر واریز کن:\n{card_number}\n"
            f"به نام: {card_holder}\n\n"
            "بعد از واریز، عکس رسید رو همینجا بفرست."
        )
        return

    if cb_data.startswith("ord_ok:") or cb_data.startswith("ord_no:"):
        if from_chat != admin_chat_id:
            _telegram_answer_callback(token, cb_id, "فقط ادمین می‌تونه این کارو بکنه.")
            return
        order_id = cb_data.split(":", 1)[1]
        order = _find_order(data, order_id)
        if not order:
            _telegram_answer_callback(token, cb_id, "سفارش پیدا نشد.")
            return
        if order["status"] != "pending_review":
            _telegram_answer_callback(token, cb_id, "این سفارش قبلاً رسیدگی شده.")
            return

        if cb_data.startswith("ord_no:"):
            order["status"] = "rejected"
            save_db(data)
            _telegram_answer_callback(token, cb_id, "رد شد.")
            _telegram_send(token, order["chat_id"], "متاسفانه رسید پرداختت تایید نشد. با پشتیبانی در تماس باش.")
            return

        base_username = f"tg{order['chat_id']}"
        username = base_username
        suffix = 1
        while any(u["username"] == username for u in data["users"]):
            suffix += 1
            username = f"{base_username}_{suffix}"
        user, err = _create_user_internal(
            data, username, order.get("data_limit_gb", 0), order.get("days_valid", 0), order.get("device_limit", 2)
        )
        if user is None:
            _telegram_answer_callback(token, cb_id, "ساخت کاربر ناموفق بود.")
            _telegram_send(token, admin_chat_id, f"❌ ساخت کاربر برای سفارش {order_id} شکست خورد: {err}")
            return
        order["status"] = "approved"
        order["username"] = user["username"]
        save_db(data)
        _telegram_answer_callback(token, cb_id, "تایید شد ✅")
        sub_link = f"https://{host}/sub/{user['subscription_token']}"
        _telegram_send(
            token, order["chat_id"],
            f"✅ پرداختت تایید شد! کانفیگت آماده‌ست:\n\n{sub_link}\n\n"
            f"حجم: {format_bytes_gb(user.get('data_limit_bytes'))}\n"
            f"انقضا: {format_expire(user.get('expire_at'))}"
        )
        if err:
            _telegram_send(token, admin_chat_id, f"⚠️ کاربر ساخته شد ولی یه مشکل کوچیک پیش اومد: {err}")
        return


def _handle_admin_message(token, data, telegram, message, chat_id, host):
    """دستورهای متنی ادمین (همون رفتار قبلی، بدون تغییر)."""
    text = (message.get("text") or "").strip()

    if not text or text.startswith("/start") or text.startswith("/help"):
        _telegram_send(token, chat_id, TELEGRAM_HELP_TEXT)
        return

    if text.startswith("/backup"):
        payload = _build_backup_payload(data)
        import json as _json
        content = _json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        _telegram_send_document(token, chat_id, "speedpanel-backup.json", content, caption="بکاپ پنل")
        return

    if text.startswith("/newuser"):
        parts = text.split()[1:]
        if not parts:
            _telegram_send(token, chat_id, "فرمت درست:\n/newuser نام_کاربری حجم_گیگ مدت_روز تعداد_دستگاه\nمثال: /newuser ali 50 30 2")
            return
        username = parts[0]
        try:
            data_limit_gb = float(parts[1]) if len(parts) > 1 else 0
            days_valid = int(parts[2]) if len(parts) > 2 else 0
            device_limit = int(parts[3]) if len(parts) > 3 else 2
        except ValueError:
            _telegram_send(token, chat_id, "حجم، مدت و تعداد دستگاه باید عدد باشن. مثال درست:\n/newuser ali 50 30 2")
            return

        user, err = _create_user_internal(data, username, data_limit_gb, days_valid, device_limit)
        if user is None:
            _telegram_send(token, chat_id, f"❌ {err}")
            return

        sub_link = f"https://{host}/sub/{user['subscription_token']}"
        reply = (
            f"✅ کاربر ساخته شد: {user['username']}\n"
            f"حجم: {format_bytes_gb(user.get('data_limit_bytes'))}\n"
            f"انقضا: {format_expire(user.get('expire_at'))}\n\n"
            f"لینک اشتراک:\n{sub_link}"
        )
        if err:
            reply += f"\n\n⚠️ {err}"
        _telegram_send(token, chat_id, reply)
        return

    _telegram_send(token, chat_id, "دستور شناخته نشد.\n\n" + TELEGRAM_HELP_TEXT)


@app.post("/telegram/webhook/{token}")
async def telegram_webhook(token: str, request: Request):
    """تلگرام برای هر پیامی که به ربات فرستاده بشه، یه درخواست به همین مسیر
    می‌زنه. توکن توی خود آدرس چک می‌شه تا کسی غیر از تلگرام نتونه پیام جعلی
    بفرسته.

    این ربات دو نقش داره:
    - چت ادمین (اولین کسی که بعد از وصل‌کردن /start بزنه) → همون دستورهای
      مدیریتی قبلی (/newuser، /backup، /help).
    - هر چت دیگه‌ای → یه مشتری بالقوه‌ست و منوی خرید (تعرفه‌ها) رو می‌بینه؛
      بعد از انتخاب تعرفه و فرستادن عکس رسید، سفارشش برای تایید/رد برای ادمین
      فرستاده می‌شه و با تاییدِ ادمین، کاربرش خودکار ساخته و لینکش براش
      فرستاده می‌شه."""
    data = get_db()
    telegram = data["settings"].get("telegram") or {}
    if not telegram.get("connected") or telegram.get("token") != token:
        raise HTTPException(status_code=404, detail="ربات متصل نیست")

    try:
        update = await request.json()
    except Exception:
        return {"ok": True}

    host = request.headers.get("host") or data["settings"].get("server_host_name") or "localhost"
    admin_chat_id = telegram.get("admin_chat_id")

    callback = update.get("callback_query")
    if callback:
        _handle_telegram_callback(token, data, telegram, callback, admin_chat_id, host)
        return {"ok": True}

    message = update.get("message") or update.get("edited_message")
    if not message:
        return {"ok": True}
    chat_id = message.get("chat", {}).get("id")
    if not chat_id:
        return {"ok": True}

    # اولین نفری که پیام بده، صاحب ربات (ادمین) می‌شه — فقط یه بار، تا وقتی
    # دوباره از پنل «قطع اتصال» و «اتصال» بشه.
    if admin_chat_id is None:
        telegram["admin_chat_id"] = chat_id
        data["settings"]["telegram"] = telegram
        save_db(data)
        _telegram_send(token, chat_id, "این ربات به‌عنوان ربات شخصیِ مدیر پنل ثبت شد. ✅\n\n" + TELEGRAM_HELP_TEXT)
        return {"ok": True}

    if chat_id == admin_chat_id:
        _handle_admin_message(token, data, telegram, message, chat_id, host)
        return {"ok": True}

    # هر چت دیگه‌ای، یعنی یه مشتری بالقوه.
    _handle_customer_message(token, data, telegram, message, chat_id, host)
    return {"ok": True}


# ==================== مشخصات سرور ====================

@app.get("/admin/server-specs")
def server_specs(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    swap = psutil.swap_memory()
    uptime_seconds = int(time.time() - START_TIME)
    return {
        "cpu_cores": psutil.cpu_count(logical=True) or 1,
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "ram_total_gb": round(vm.total / (1024 ** 3), 1),
        "ram_used_gb": round(vm.used / (1024 ** 3), 1),
        "ram_percent": vm.percent,
        "disk_total_gb": round(disk.total / (1024 ** 3), 1),
        "disk_used_gb": round(disk.used / (1024 ** 3), 1),
        "swap_total_gb": round(swap.total / (1024 ** 3), 1),
        "swap_used_gb": round(swap.used / (1024 ** 3), 1),
        "swap_percent": swap.percent,
        "uptime_seconds": uptime_seconds,
        "host": data["settings"].get("server_host_name", "Railway"),
        "region": data["settings"].get("server_region", ""),
    }


# ==================== رویداد شروع ====================

LIMIT_CHECK_INTERVAL_SECONDS = 120


def _limit_enforcement_loop():
    """هر چند دقیقه یه بار (مستقل از اینکه کسی پنل رو باز کرده باشه یا نه)
    چک می‌کنه کاربری حجمش تموم شده یا تاریخش گذشته؛ اگه آره، خاموشش می‌کنه و
    Xray رو ری‌استارت می‌کنه تا کانفیگش واقعاً قطع بشه. بدون این حلقه، کاربر
    فقط وقتی قطع می‌شد که ادمین خودش صفحه‌ی کاربرها رو باز می‌کرد."""
    while True:
        time.sleep(LIMIT_CHECK_INTERVAL_SECONDS)
        try:
            data = get_db()
            xray_manager.refresh_all_traffic(data)
            changed = xray_manager.enforce_limits(data)
            save_db(data)
            if changed:
                xray_manager.apply_and_restart(data)
        except Exception:
            # این حلقه نباید هیچ‌وقت کلاً بمیره؛ یه خطای موقت رو نادیده می‌گیریم
            # و دور بعدی دوباره امتحان می‌کنیم.
            pass


@app.on_event("startup")
def on_startup():
    data = get_db()
    ensure_admin_password(data)
    xray_manager.apply_and_restart(data)
    threading.Thread(target=_limit_enforcement_loop, daemon=True).start()
