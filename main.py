import os
import platform
import secrets
import time
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import bcrypt
import httpx
import psutil
from fastapi import FastAPI, Header, HTTPException
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


class SettingsBody(BaseModel):
    brand_name: str | None = None
    support_telegram: str | None = None
    server_region: str | None = None
    server_host_name: str | None = None
    latest_version: str | None = None
    update_message: str | None = None


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
    save_db(data)
    return data["users"]


@app.post("/users")
def create_user(body: CreateUserBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    if any(u["username"] == body.username for u in data["users"]):
        raise HTTPException(status_code=400, detail="این نام کاربری قبلاً ساخته شده")
    if not body.username.strip():
        raise HTTPException(status_code=400, detail="نام کاربری نمی‌تواند خالی باشد")

    expire_at = None
    if body.days_valid and body.days_valid > 0:
        expire_at = (datetime.now(timezone.utc) + timedelta(days=body.days_valid)).isoformat()

    user = {
        "username": body.username.strip(),
        "uuid": str(uuidlib.uuid4()),
        "subscription_token": secrets.token_urlsafe(16),
        "data_limit_bytes": int(body.data_limit_gb * (1024 ** 3)) if body.data_limit_gb else 0,
        "used_traffic_bytes": 0,
        "device_limit": body.device_limit,
        "speed_limit_mbps": body.speed_limit_mbps,
        "expire_at": expire_at,
        "created_at": db.now_iso(),
        "is_active": True,
    }
    data["users"].append(user)
    save_db(data)
    xray_manager.apply_and_restart(data)
    return user


@app.patch("/users/{username}/toggle")
def toggle_user(username: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    for u in data["users"]:
        if u["username"] == username:
            u["is_active"] = not u["is_active"]
            save_db(data)
            xray_manager.apply_and_restart(data)
            return {"ok": True, "is_active": u["is_active"]}
    raise HTTPException(status_code=404, detail="کاربر پیدا نشد")


@app.delete("/users/{username}")
def delete_user(username: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u["username"] != username]
    if len(data["users"]) == before:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
    save_db(data)
    xray_manager.apply_and_restart(data)
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
    link = build_vless_link(user, domain)

    if is_vpn_app(user_agent):
        import base64
        return PlainTextResponse(base64.b64encode(link.encode("utf-8")).decode("utf-8"))

    with open(os.path.join(STATIC_DIR, "sub.html"), "r", encoding="utf-8") as f:
        page = f.read()
    page = (
        page.replace("__BRAND__", data["settings"].get("brand_name") or "Speed Panel")
            .replace("__USERNAME__", user["username"])
            .replace("__VLESS_LINK__", link)
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
    }


@app.put("/admin/settings")
def put_settings(body: SettingsBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    s = data["settings"]
    for field in ("brand_name", "support_telegram", "server_region", "server_host_name",
                  "latest_version", "update_message"):
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
    xray_manager.apply_and_restart(data)
    return {"ok": True}


@app.get("/admin/routing-rules")
def routing_rules(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    return {"rules": xray_manager.build_routing_rules(data["settings"])}


@app.get("/admin/backup")
def backup(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    payload = {
        "format": "speedpanel-backup",
        "users": data["users"],
        "settings": {k: v for k, v in data["settings"].items()
                      if k not in ("admin_password_hash", "active_token")},
    }
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
        data["users"].append(u)
        existing_usernames.add(u["username"])
        added += 1
    if body.restore_settings and body.settings:
        for k, v in body.settings.items():
            if k not in ("admin_password_hash", "active_token"):
                data["settings"][k] = v
    save_db(data)
    xray_manager.apply_and_restart(data)
    return {"ok": True, "added": added, "skipped": skipped}


@app.post("/admin/telegram/connect")
def telegram_connect(body: TelegramConnectBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    import httpx
    try:
        res = httpx.get(f"https://api.telegram.org/bot{body.token}/getMe", timeout=10)
        info = res.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اتصال به تلگرام برقرار نشد")
    if not info.get("ok"):
        raise HTTPException(status_code=400, detail="توکن ربات نامعتبر است")
    username = info["result"]["username"]
    data["settings"]["telegram"] = {"connected": True, "token": body.token, "username": username}
    save_db(data)
    return {"ok": True, "username": username}


@app.post("/admin/telegram/disconnect")
def telegram_disconnect(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    data["settings"]["telegram"] = {"connected": False, "token": None, "username": None}
    save_db(data)
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

@app.on_event("startup")
def on_startup():
    data = get_db()
    ensure_admin_password(data)
    xray_manager.apply_and_restart(data)
