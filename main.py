import base64
import io
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

    with open(os.path.join(STATIC_DIR, "sub.html"), "r", encoding="utf-8") as f:
        page = f.read()
    page = (
        page.replace("__BRAND__", data["settings"].get("brand_name") or "Speed Panel")
            .replace("__USERNAME__", user["username"])
            .replace("__VLESS_LINK__", primary_link)
            .replace("__QR_DATA_URI__", _build_qr_data_uri(primary_link))
            .replace("__DATA_LIMIT__", format_bytes_gb(user.get("data_limit_bytes")))
            .replace("__EXPIRE__", format_expire(user.get("expire_at")))
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


TELEGRAM_HELP_TEXT = (
    "دستورهای ربات (فقط برای مدیر پنل):\n\n"
    "/newuser نام_کاربری حجم_گیگ مدت_روز تعداد_دستگاه\n"
    "مثال: /newuser ali 50 30 2\n"
    "(حجم، مدت و تعداد دستگاه اختیاری‌ان؛ پیش‌فرض: نامحدود، نامحدود، ۲)\n\n"
    "/backup\n"
    "گرفتن فایل بکاپ کامل (کاربرها + تنظیمات)\n\n"
    "/help\n"
    "نمایش همین راهنما"
)


@app.post("/telegram/webhook/{token}")
async def telegram_webhook(token: str, request: Request):
    """تلگرام برای هر پیامی که به ربات فرستاده بشه، یه درخواست به همین مسیر
    می‌زنه. توکن توی خود آدرس چک می‌شه تا کسی غیر از تلگرام نتونه پیام جعلی
    بفرسته. این ربات کاملاً خصوصیه: فقط اولین چتی که بعد از وصل‌کردن به ربات
    پیام بده (یعنی خودِ ادمین) به‌عنوان «مدیر» ثبت می‌شه و فقط همون چت اجازه‌ی
    دستور داره؛ هیچ کاربر دیگه‌ای (حتی اگه توکن ربات رو هم بفهمه) نمی‌تونه
    باهاش حرف بزنه یا چیزی از پنل ببینه."""
    data = get_db()
    telegram = data["settings"].get("telegram") or {}
    if not telegram.get("connected") or telegram.get("token") != token:
        raise HTTPException(status_code=404, detail="ربات متصل نیست")

    try:
        update = await request.json()
    except Exception:
        return {"ok": True}

    message = update.get("message") or update.get("edited_message")
    if not message:
        return {"ok": True}
    chat_id = message.get("chat", {}).get("id")
    text = (message.get("text") or "").strip()
    if not chat_id:
        return {"ok": True}

    admin_chat_id = telegram.get("admin_chat_id")

    # اولین نفری که پیام بده، صاحب ربات (ادمین) می‌شه — فقط یه بار، تا وقتی
    # دوباره از پنل «قطع اتصال» و «اتصال» بشه.
    if admin_chat_id is None:
        telegram["admin_chat_id"] = chat_id
        data["settings"]["telegram"] = telegram
        save_db(data)
        _telegram_send(token, chat_id, "این ربات به‌عنوان ربات شخصیِ مدیر پنل ثبت شد. ✅\n\n" + TELEGRAM_HELP_TEXT)
        return {"ok": True}

    # هر چت دیگه‌ای غیر از همون ادمینِ ثبت‌شده، کاملاً نادیده گرفته می‌شه.
    if chat_id != admin_chat_id:
        return {"ok": True}

    if not text or text.startswith("/start") or text.startswith("/help"):
        _telegram_send(token, chat_id, TELEGRAM_HELP_TEXT)
        return {"ok": True}

    if text.startswith("/backup"):
        payload = _build_backup_payload(data)
        import json as _json
        content = _json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        _telegram_send_document(token, chat_id, "speedpanel-backup.json", content, caption="بکاپ پنل")
        return {"ok": True}

    if text.startswith("/newuser"):
        parts = text.split()[1:]
        if not parts:
            _telegram_send(token, chat_id, "فرمت درست:\n/newuser نام_کاربری حجم_گیگ مدت_روز تعداد_دستگاه\nمثال: /newuser ali 50 30 2")
            return {"ok": True}
        username = parts[0]
        try:
            data_limit_gb = float(parts[1]) if len(parts) > 1 else 0
            days_valid = int(parts[2]) if len(parts) > 2 else 0
            device_limit = int(parts[3]) if len(parts) > 3 else 2
        except ValueError:
            _telegram_send(token, chat_id, "حجم، مدت و تعداد دستگاه باید عدد باشن. مثال درست:\n/newuser ali 50 30 2")
            return {"ok": True}

        user, err = _create_user_internal(data, username, data_limit_gb, days_valid, device_limit)
        if user is None:
            _telegram_send(token, chat_id, f"❌ {err}")
            return {"ok": True}

        host = request.headers.get("host") or "localhost"
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
        return {"ok": True}

    _telegram_send(token, chat_id, "دستور شناخته نشد.\n\n" + TELEGRAM_HELP_TEXT)
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
