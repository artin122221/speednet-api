import base64
import hashlib
import io
import json
import math
import os
import platform
import secrets
import threading
import time
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import bcrypt
import httpx
import psutil
import qrcode
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from . import db, subpage, xray_manager

APP_VERSION = "2.0"
START_TIME = time.time()
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

import base64 as _b64
_u = os.environ.get("UPDATE_SERVER_URL", "") or _b64.b64decode(
    "aHR0cHM6Ly9saWNlbnNlLXNlcnZlci1wcm9kdWN0aW9uLTg2M2MudXAucmFpbHdheS5hcHA="
).decode()
UPDATE_SERVER_URL = _u.rstrip("/")

# آدرس صفحه‌ی پروژه برای پیام «حمایت با ستاره». از سمت سرور به پنل داده می‌شه، نه
# داخل فایل صفحه‌ی HTML.
STAR_URL = _b64.b64decode("aHR0cHM6Ly9naXRodWIuY29tL2FydGluMTIyMjIxL3NwZWVkbmV0LWFwaQ==").decode()

# نتیجه‌ی آخرین چک با سرور مرکزی رو چند دقیقه نگه می‌داریم تا هر درخواست به
# پنل، یه تماس شبکه‌ی جدید با اون سرور نزنه (هم سریع‌تره هم فشار کمتری میاره).
_ban_cache = {"banned": False, "message": "", "checked_at": 0.0}
BAN_CHECK_INTERVAL_SECONDS = 120

app = FastAPI(title="Speed X4G API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def _unhandled_error(request: Request, exc: Exception):
    """به‌جای متن خام «Internal Server Error»، یه JSON خوانا برمی‌گردونیم تا پنل
    دلیل خطا رو نشون بده. جزئیات فقط برای مسیرهای ادمین داده می‌شه."""
    import traceback
    traceback.print_exc()
    detail = "خطای داخلی سرور"
    if request.url.path.startswith("/admin"):
        detail += f" ({type(exc).__name__}: {str(exc)[:200]})"
    return JSONResponse(status_code=500, content={"detail": detail})


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


def _raise_if_banned(data):
    """اگه این نصبِ پنل از سرور مرکزی بن شده باشه، همینجا جلوی هر دسترسی‌ای رو
    می‌گیره — چه ادمین اصلی باشه چه ادمین فرعی."""
    banned, ban_message = is_remotely_banned(data, data["settings"].get("server_host_name", ""))
    if banned:
        detail = "دسترسی این پنل مسدود شده است."
        if ban_message:
            detail += f" دلیل: {ban_message}"
        raise HTTPException(status_code=403, detail=detail)


def require_admin(authorization: str | None):
    """فقط برای ادمین اصلی (root) — تنظیمات، بکاپ، ربات تلگرام، مدیریت
    ادمین‌های فرعی و... فقط دست خودشه."""
    data = get_db()
    ensure_admin_password(data)
    _raise_if_banned(data)
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
    active = data["settings"].get("active_token")
    if not token or not active or token != active:
        raise HTTPException(status_code=401, detail="نشست شما منقضی شده، دوباره وارد شوید")
    return data


def require_identity(authorization: str | None):
    """هم ادمین اصلی و هم ادمین‌های فرعی رو قبول می‌کنه (برای صفحه‌ی کاربرها و
    داشبورد). برمی‌گردونه (data, identity) که identity یا {"role":"root"} ـه
    یا {"role":"admin","username":...}."""
    data = get_db()
    ensure_admin_password(data)
    _raise_if_banned(data)
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
    if not token:
        raise HTTPException(status_code=401, detail="نشست شما منقضی شده، دوباره وارد شوید")
    if data["settings"].get("active_token") == token:
        return data, {"role": "root", "username": "admin"}
    for admin in data.get("admins", []):
        if admin.get("active_token") and admin["active_token"] == token:
            if not admin.get("is_active", True):
                raise HTTPException(status_code=403, detail="حساب شما غیرفعال شده است")
            return data, {"role": "admin", "username": admin["username"]}
    raise HTTPException(status_code=401, detail="نشست شما منقضی شده، دوباره وارد شوید")


_FINGERPRINTS = ("chrome", "firefox", "safari", "edge")


def _fp(user, proto: str):
    """اثر انگشت TLS یکسان برای همه‌ی لینک‌ها، یه علامت قابل‌تشخیصه. پس برای هر
    کاربر/پروتکل یکی از مرورگرهای واقعی رو (ثابت و تکرارپذیر) انتخاب می‌کنیم."""
    h = hashlib.sha256(f"{user['uuid']}:{proto}".encode()).digest()
    return _FINGERPRINTS[h[0] % len(_FINGERPRINTS)]


def build_vless_link(user, request_host: str):
    """لینک واقعی VLESS که با دامنه‌ی ریلوی و روی TLS/WebSocket کار می‌کنه."""
    uuid_ = user["uuid"]
    path = xray_manager.VLESS_WS_PATH
    remark = user["username"]
    return (
        f"vless://{uuid_}@{request_host}:443"
        f"?encryption=none&security=tls&type=ws&host={request_host}&path={path}&sni={request_host}&fp={_fp(user, 'ws')}&alpn=http/1.1"
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
    remark = f"{user['username']}-Reality"
    return (
        f"vless://{uuid_}@{host}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={xray_manager.REALITY_SERVER_NAME}&fp={_fp(user, 'reality')}&pbk={public_key}&sid={short_id or ''}&type=tcp"
        f"#{remark}"
    )


def _tls_ws_tail(host, path, net, extra="", fp="chrome"):
    """بخش مشترک لینک‌هایی که پشت دامنه‌ی ریلوی (TLS روی ۴۴۳) رد می‌شن."""
    return (
        f"security=tls&type={net}&host={host}&path={quote(path, safe='/')}"
        f"&sni={host}&fp={fp}&alpn={extra or 'http/1.1'}"
    )


def build_vmess_ws_link(user, host):
    obj = {
        "v": "2", "ps": f"{user['username']}-VMess", "add": host, "port": "443",
        "id": user["uuid"], "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": host, "path": xray_manager.VMESS_WS_PATH, "tls": "tls",
        "sni": host, "alpn": "http/1.1", "fp": _fp(user, "vmess"),
    }
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return "vmess://" + base64.b64encode(raw).decode("ascii")


def build_trojan_ws_link(user, host):
    return (
        f"trojan://{user['uuid']}@{host}:443?"
        + _tls_ws_tail(host, xray_manager.TROJAN_WS_PATH, "ws", fp=_fp(user, "trojan"))
        + f"#{user['username']}-Trojan"
    )


def build_vless_httpupgrade_link(user, host):
    return (
        f"vless://{user['uuid']}@{host}:443?encryption=none&"
        + _tls_ws_tail(host, xray_manager.HTTPUPGRADE_PATH, "httpupgrade", fp=_fp(user, "hu"))
        + f"#{user['username']}-HTTPUpgrade"
    )


def build_vless_xhttp_link(user, host):
    return (
        f"vless://{user['uuid']}@{host}:443?encryption=none&"
        + _tls_ws_tail(host, xray_manager.XHTTP_PATH, "xhttp", "h2,http/1.1", fp=_fp(user, "xhttp"))
        + f"&mode=auto#{user['username']}-XHTTP"
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
    group_ids: list[str] = []


class UpdateUserBody(BaseModel):
    data_limit_gb: float | None = None
    days_valid: int | None = None
    device_limit: int | None = None
    speed_limit_mbps: int | None = None
    reset_usage: bool = False
    group_ids: list[str] | None = None


class GroupBody(BaseModel):
    name: str


class GroupItemBody(BaseModel):
    # kind=builtin → protocol یکی از vless_ws یا vless_reality؛ kind=custom → link کامل
    kind: str
    protocol: str = ""
    label: str = ""
    link: str = ""


class SettingsBody(BaseModel):
    brand_name: str | None = None
    support_telegram: str | None = None
    server_region: str | None = None
    server_host_name: str | None = None
    latest_version: str | None = None
    update_message: str | None = None
    reality_external_host: str | None = None
    reality_external_port: str | None = None
    sub_theme: str | None = None


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


class FullRestoreBody(BaseModel):
    users: list = []
    settings: dict | None = None
    config_groups: list | None = None
    admins: list | None = None
    plans: list | None = None
    orders: list | None = None
    ws_path: str | None = None


class RestoreBody(BaseModel):
    users: list
    settings: dict | None = None
    restore_settings: bool = False


class AdminCreateBody(BaseModel):
    username: str
    password: str
    data_limit_gb: float = 0  # ۰ یعنی نامحدود


class AdminUpdateBody(BaseModel):
    data_limit_gb: float | None = None
    is_active: bool | None = None
    reset_usage: bool = False
    new_password: str | None = None


# ==================== وضعیت عمومی (بدون نیاز به ورود) ====================

def check_update_server(data, request_host: str = ""):
    """اگه UPDATE_SERVER_URL تنظیم شده باشه، این پنل خودش رو (با یه شناسه‌ی
    یکتا) به سرور مرکزی معرفی می‌کنه: هم می‌پرسه نسخه‌ی جدیدی اومده یا نه، هم
    می‌فهمه آیا همین نصب از اونجا بن شده یا نه. نتیجه چند دقیقه کش می‌شه تا
    هر درخواست به پنل یه تماس شبکه‌ی جدید با اون سرور نزنه."""
    global _ban_cache
    if not UPDATE_SERVER_URL:
        return None
    now = time.time()
    if now - _ban_cache["checked_at"] < BAN_CHECK_INTERVAL_SECONDS and _ban_cache.get("_last_info") is not None:
        return _ban_cache["_last_info"]
    try:
        res = httpx.get(
            f"{UPDATE_SERVER_URL}/check",
            params={
                "instance_id": data["instance_id"],
                "version": APP_VERSION,
                # دامنه‌ی واقعی ریلوی (اگه باشه) به‌جای متن آزادی که ادمین تایپ کرده
                "domain": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip() or request_host,
            },
            timeout=5,
        )
        info = res.json()
        _ban_cache = {
            "banned": bool(info.get("banned")),
            "message": info.get("ban_reason") or "",
            "checked_at": now,
            "_last_info": info,
        }
        return info
    except Exception:
        # اگه سرور مرکزی موقتاً در دسترس نبود، پنل رو به‌خاطر همین قفل نمی‌کنیم؛
        # فقط همون نتیجه‌ی قبلی (اگه قبلاً گرفته بودیم) نگه داشته می‌شه
        return _ban_cache.get("_last_info")


def is_remotely_banned(data, request_host: str = ""):
    """خروجی: (banned: bool, message: str). اگه UPDATE_SERVER_URL تنظیم نشده
    باشه، همیشه False برمی‌گرده — یعنی این قفل فقط برای نصب‌هایی فعاله که به
    سرور مرکزی وصلن."""
    check_update_server(data, request_host)
    return _ban_cache["banned"], _ban_cache["message"]


# نام‌های خوانا برای کدهای منطقه‌ای که خودِ Railway موقع دیپلوی به‌صورت
# خودکار توی این متغیر محیطی می‌ذاره — نیازی نیست خودت جایی تایپش کنی.
RAILWAY_REGION_NAMES = {
    "us-west2": "ایالات متحده — کالیفرنیا",
    "us-east4-eqdc4a": "ایالات متحده — ویرجینیا",
    "europe-west4-drams3a": "اروپا — آمستردام",
    "asia-southeast1-eqsg3a": "آسیا — سنگاپور",
}


def detect_server_region(settings):
    """اول سعی می‌کنه منطقه‌ای که خودِ Railway انتخاب کرده رو خودکار بفهمه؛
    اگه این متغیر محیطی خالی/در دسترس نبود، برمی‌گرده به همون مقداری که خودت
    دستی توی تنظیمات پنل وارد کردی."""
    code = os.environ.get("RAILWAY_REPLICA_REGION", "").strip()
    if code:
        return RAILWAY_REGION_NAMES.get(code, code)
    return settings.get("server_region", "")


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

    banned, ban_message = is_remotely_banned(data, settings.get("server_host_name", ""))

    return {
        "host": settings.get("server_host_name", "Railway"),
        "region": detect_server_region(settings),
        "version": APP_VERSION,
        "latest_version": latest_version,
        "update_available": update_available,
        "update_changelog": changelog,
        "update_download_url": download_url,
        "update_message": settings.get("update_message", ""),
        "star_url": STAR_URL,
        "brand_name": (settings.get("brand_name") if settings.get("brand_name") not in (None, "", "Speed Panel") else "Speed X4G"),
        "support_telegram": settings.get("support_telegram", ""),
        "banned": banned,
        "ban_message": ban_message,
    }


_p = os.environ.get("ADMIN_PANEL_PATH", "sp-admin-7k2q9").strip("/")


@app.get(f"/{_p}", response_class=HTMLResponse)
def panel():
    return FileResponse(os.path.join(STATIC_DIR, "panel.html"))


DECOY_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#f6f7f9;color:#333}main{text-align:center;padding:24px}h1{font-size:22px;margin:0 0 8px;font-weight:600}p{margin:0;color:#777;font-size:14px}</style></head><body><main><h1>Site under maintenance</h1><p>We will be back shortly.</p></main></body></html>"""


@app.get("/", response_class=HTMLResponse)
def root():
    # صفحه‌ی ساده و بی‌خطر به‌جای خطای FastAPI: کسی که آدرس رو حدس می‌زنه یا
    # اسکن می‌کنه، یه سایت معمولی می‌بینه نه یه پنل
    return HTMLResponse(DECOY_PAGE)


# ==================== ورود ====================

@app.post("/admin/login")
def login(body: LoginBody):
    data = get_db()
    ensure_admin_password(data)
    _raise_if_banned(data)
    username = (body.username or "admin").strip()

    if username == "admin":
        if not check_password(body.password, data["settings"]["admin_password_hash"]):
            raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
        token = secrets.token_hex(32)
        data["settings"]["active_token"] = token
        save_db(data)
        return {"token": token, "role": "root", "username": "admin"}

    # ورود یه ادمین فرعی با نام‌کاربری/رمز خودش
    admin = next((a for a in data.get("admins", []) if a["username"] == username), None)
    if not admin or not check_password(body.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    if not admin.get("is_active", True):
        raise HTTPException(status_code=403, detail="حساب شما غیرفعال شده است")
    token = secrets.token_hex(32)
    admin["active_token"] = token
    save_db(data)
    return {"token": token, "role": "admin", "username": username}


@app.post("/admin/change-password")
def change_password(body: ChangePasswordBody, authorization: str | None = Header(default=None)):
    """هم ادمین اصلی رمز خودش رو اینجا عوض می‌کنه، هم هر ادمین فرعی رمز خودش رو."""
    data, identity = require_identity(authorization)
    if len(body.new_password) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")

    if identity["role"] == "root":
        if not check_password(body.current_password, data["settings"]["admin_password_hash"]):
            raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
        data["settings"]["admin_password_hash"] = hash_password(body.new_password)
        data["settings"]["active_token"] = None  # اجبار به ورود دوباره
    else:
        admin = next(a for a in data["admins"] if a["username"] == identity["username"])
        if not check_password(body.current_password, admin["password_hash"]):
            raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
        admin["password_hash"] = hash_password(body.new_password)
        admin["active_token"] = None

    save_db(data)
    return {"ok": True}


# ==================== کاربران ====================

@app.get("/users")
def list_users(authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    xray_manager.refresh_all_traffic(data)
    changed = xray_manager.enforce_limits(data)
    changed = xray_manager.enforce_admin_quotas(data) or changed
    save_db(data)
    if changed:
        try:
            xray_manager.apply_and_restart(data)
        except RuntimeError:
            pass
    users = data["users"]
    if identity["role"] == "admin":
        users = [u for u in users if u.get("created_by") == identity["username"]]
    return users


def _clean_group_ids(data, group_ids):
    """فقط شناسه‌هایی که واقعاً گروه وجود دارن نگه داشته می‌شن."""
    valid = {g["id"] for g in data.get("config_groups", [])}
    return [gid for gid in (group_ids or []) if gid in valid]


def _create_user_internal(data, username, data_limit_gb=0, days_valid=0, device_limit=2, speed_limit_mbps=None, created_by="root", group_ids=None):
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
        "disabled_reason": None,
        "created_by": created_by,
        "group_ids": _clean_group_ids(data, group_ids),
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
    data, identity = require_identity(authorization)
    created_by = "root" if identity["role"] == "root" else identity["username"]

    if identity["role"] == "admin":
        admin = next((a for a in data.get("admins", []) if a["username"] == identity["username"]), None)
        if not admin or not admin.get("is_active", True):
            raise HTTPException(status_code=403, detail="حساب شما غیرفعال شده است")
        limit = admin.get("data_limit_bytes")
        if limit:
            used = xray_manager.admin_used_bytes(data, identity["username"])
            if used >= limit:
                raise HTTPException(
                    status_code=403,
                    detail="حجم شما تمام شده؛ برای ساخت کانفیگ جدید باید از ادمین اصلی حجم بیشتری بگیرید",
                )

    user, err = _create_user_internal(
        data, body.username, body.data_limit_gb, body.days_valid, body.device_limit, body.speed_limit_mbps,
        created_by=created_by, group_ids=body.group_ids,
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


def _check_user_access(user, identity):
    """ادمین فرعی فقط به کانفیگ‌های خودش دسترسی داره؛ ادمین اصلی به همه."""
    if identity["role"] == "admin" and user.get("created_by") != identity["username"]:
        raise HTTPException(status_code=403, detail="شما به این کانفیگ دسترسی ندارید")


@app.patch("/users/{username}/toggle")
def toggle_user(username: str, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    for u in data["users"]:
        if u["username"] == username:
            _check_user_access(u, identity)
            u["is_active"] = not u["is_active"]
            # روشن/خاموش‌کردن دستی توسط ادمین؛ دیگه دلیلش «اتمام حجم» نیست
            u["disabled_reason"] = None if u["is_active"] else "manual"
            save_db(data)
            _apply_and_restart_safe(data)
            return {"ok": True, "is_active": u["is_active"]}
    raise HTTPException(status_code=404, detail="کاربر پیدا نشد")


@app.patch("/users/{username}")
def update_user(username: str, body: UpdateUserBody, authorization: str | None = Header(default=None)):
    """ویرایش یه کاربر موجود: حجم، مدت اعتبار، تعداد دستگاه و محدودیت سرعت."""
    data, identity = require_identity(authorization)
    user = next((u for u in data["users"] if u["username"] == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
    _check_user_access(user, identity)

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
    if body.group_ids is not None:
        user["group_ids"] = _clean_group_ids(data, body.group_ids)
    if body.reset_usage:
        # فقط ادمین اصلی می‌تونه مصرف یه کانفیگ رو صفر کنه؛ وگرنه ادمین فرعی
        # می‌تونست با همین دکمه، سهمیه‌ی مصرفیِ خودش رو مجانی صفر کنه
        if identity["role"] != "root":
            raise HTTPException(status_code=403, detail="فقط ادمین اصلی می‌تونه مصرف یه کانفیگ رو صفر کند")
        user["used_traffic_bytes"] = 0
        user["traffic_baseline_bytes"] = 0

    # اگه این کاربر قبلاً به‌خاطر اتمام حجم یا انقضا خاموش شده بود، الان که
    # شارژ شد یا تمدید شد، همین‌جا خودکار دوباره روشنش می‌کنیم
    xray_manager.enforce_limits(data)
    xray_manager.enforce_admin_quotas(data)

    save_db(data)
    _apply_and_restart_safe(data)
    return user


@app.delete("/users/{username}")
def delete_user(username: str, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    target = next((u for u in data["users"] if u["username"] == username), None)
    if not target:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
    _check_user_access(target, identity)

    # اگه این کانفیگ مال یه ادمین فرعی بود، حجمی که مصرف کرده قبل از حذف توی
    # «حجم باقی‌مونده»ی اون ادمین ذخیره می‌شه تا حذف‌کردن کانفیگ سهمیه رو آزاد
    # نکنه (وگرنه ادمین فرعی می‌تونست با حذف و ساخت دوباره، حجمش رو ریست کنه)
    created_by = target.get("created_by")
    if created_by and created_by != "root":
        admin = next((a for a in data.get("admins", []) if a["username"] == created_by), None)
        if admin is not None:
            admin["banked_used_bytes"] = admin.get("banked_used_bytes", 0) + target.get("used_traffic_bytes", 0)

    data["users"] = [u for u in data["users"] if u["username"] != username]
    save_db(data)
    _apply_and_restart_safe(data)
    return {"ok": True}


# ==================== گروه‌های کانفیگ ====================
# ادمین اصلی گروه می‌سازه (مثلاً «عادی»، «ویژه»)، توی هر گروه کانفیگ/پروتکل
# اضافه می‌کنه (پروتکل‌های خودِ پنل، یا هر لینک آماده‌ی vless/vmess/trojan/ss
# مثل کانفیگ‌هایی که توی NPV Tunnel وارد می‌شه). موقع ساخت کاربر، گروه‌ها
# انتخاب می‌شن و لینک اشتراک اون کاربر فقط همون کانفیگ‌ها رو می‌ده. کاربری که
# هیچ گروهی نداره، مثل قبل پروتکل‌های خودِ پنل رو می‌گیره.

GROUP_BUILTIN_PROTOCOLS = {
    "vless_ws": "VLESS",
    "vless_reality": "VLESS + REALITY",
    "vmess_ws": "VMess",
    "trojan_ws": "Trojan",
    "vless_httpupgrade": "VLESS HTTPUpgrade",
    "vless_xhttp": "VLESS XHTTP",
}
# ترتیب پیش‌فرضِ کاربری که هیچ گروهی نداره
DEFAULT_PROTOCOL_ORDER = ["vless_reality", "vless_ws", "vmess_ws", "trojan_ws", "vless_httpupgrade", "vless_xhttp"]
GROUP_ALLOWED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")


def build_builtin_link(protocol, user, domain, settings):
    """لینک یکی از پروتکل‌های خودِ پنل، یا None اگه الان فعال نیست (مثلاً REALITY
    هنوز تنظیم نشده، یا Xray این نسخه XHTTP رو نمی‌شناسه و کنارش گذاشته شده)."""
    level = xray_manager.ACTIVE_LEVEL
    if protocol == "vless_reality":
        return build_vless_reality_link(user, settings)
    if protocol == "vless_ws":
        return build_vless_link(user, domain)
    if protocol in ("vmess_ws", "trojan_ws") and level >= 3:
        return None
    if protocol == "vless_httpupgrade" and level >= 2:
        return None
    if protocol == "vless_xhttp" and level >= 1:
        return None
    builders = {
        "vmess_ws": build_vmess_ws_link,
        "trojan_ws": build_trojan_ws_link,
        "vless_httpupgrade": build_vless_httpupgrade_link,
        "vless_xhttp": build_vless_xhttp_link,
    }
    fn = builders.get(protocol)
    return fn(user, domain) if fn else None


def collect_user_links(user, data, domain):
    settings = data["settings"]
    group_ids = user.get("group_ids") or []
    links = []

    def add(link):
        if link and link not in links:
            links.append(link)

    if not group_ids:
        for proto in DEFAULT_PROTOCOL_ORDER:
            add(build_builtin_link(proto, user, domain, settings))
        return links

    for g in data.get("config_groups", []):
        if g["id"] not in group_ids:
            continue
        for item in g.get("items", []):
            if item.get("kind") == "builtin":
                add(build_builtin_link(item.get("protocol"), user, domain, settings))
            else:
                add((item.get("link") or "").replace("{uuid}", user["uuid"]).replace("{username}", user["username"]))
    return links


def _require_root(identity):
    if identity["role"] != "root":
        raise HTTPException(status_code=403, detail="فقط ادمین اصلی می‌تونه گروه‌ها رو مدیریت کند")


@app.get("/admin/protocol-status")
def protocol_status(authorization: str | None = Header(default=None)):
    """عیب‌یابی: کدوم پروتکل‌ها فعالن و اگه نیستن چرا."""
    data, identity = require_identity(authorization)
    _require_root(identity)
    level = xray_manager.ACTIVE_LEVEL
    off_at = {"vmess_ws": 3, "trojan_ws": 3, "vless_httpupgrade": 2, "vless_xhttp": 1}
    items = []
    for key in DEFAULT_PROTOCOL_ORDER:
        if key == "vless_reality":
            on = bool(build_vless_reality_link({"id": "x", "username": "x"}, data["settings"]))
            why = "" if on else "REALITY هنوز تنظیم نشده (آدرس/پورت TCP Proxy)"
        elif key == "vless_ws":
            on, why = True, ""
        else:
            on = level < off_at[key]
            why = "" if on else "نسخه‌ی Xray این پروتکل رو نپذیرفت و کنار گذاشته شد"
        items.append({"key": key, "label": GROUP_BUILTIN_PROTOCOLS.get(key, key), "active": on, "reason": why})
    return {
        "level": level,
        "xray_version": xray_manager.xray_version(),
        "xray_running": bool(xray_manager._xray_process is not None and xray_manager._xray_process.poll() is None),
        "errors": list(xray_manager.LAST_TEST_LOG)[-3:],
        "protocols": items,
        "groups_in_use": sum(1 for u in data["users"] if u.get("group_ids")),
    }


@app.get("/admin/groups")
def list_groups(authorization: str | None = Header(default=None)):
    data, _identity = require_identity(authorization)
    return data.get("config_groups", [])


@app.post("/admin/groups")
def create_group(body: GroupBody, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    _require_root(identity)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="نام گروه نمی‌تواند خالی باشد")
    if any(g["name"] == name for g in data["config_groups"]):
        raise HTTPException(status_code=400, detail="گروهی با این نام قبلاً ساخته شده")
    group = {"id": secrets.token_hex(4), "name": name, "items": []}
    data["config_groups"].append(group)
    save_db(data)
    return group


@app.patch("/admin/groups/{group_id}")
def rename_group(group_id: str, body: GroupBody, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    _require_root(identity)
    group = next((g for g in data["config_groups"] if g["id"] == group_id), None)
    if not group:
        raise HTTPException(status_code=404, detail="گروه پیدا نشد")
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="نام گروه نمی‌تواند خالی باشد")
    group["name"] = name
    save_db(data)
    return group


@app.delete("/admin/groups/{group_id}")
def delete_group(group_id: str, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    _require_root(identity)
    data["config_groups"] = [g for g in data["config_groups"] if g["id"] != group_id]
    for u in data["users"]:
        if group_id in (u.get("group_ids") or []):
            u["group_ids"] = [gid for gid in u["group_ids"] if gid != group_id]
    save_db(data)
    return {"ok": True}


@app.post("/admin/groups/{group_id}/items")
def add_group_item(group_id: str, body: GroupItemBody, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    _require_root(identity)
    group = next((g for g in data["config_groups"] if g["id"] == group_id), None)
    if not group:
        raise HTTPException(status_code=404, detail="گروه پیدا نشد")

    if body.kind == "builtin":
        if body.protocol not in GROUP_BUILTIN_PROTOCOLS:
            raise HTTPException(status_code=400, detail="پروتکل نامعتبر است")
        if any(i.get("kind") == "builtin" and i.get("protocol") == body.protocol for i in group["items"]):
            raise HTTPException(status_code=400, detail="این پروتکل قبلاً توی این گروه اضافه شده")
        item = {
            "id": secrets.token_hex(4),
            "kind": "builtin",
            "protocol": body.protocol,
            "label": body.label.strip() or GROUP_BUILTIN_PROTOCOLS[body.protocol],
        }
    elif body.kind == "custom":
        link = body.link.strip()
        if not link.lower().startswith(GROUP_ALLOWED_SCHEMES):
            raise HTTPException(status_code=400, detail="لینک باید با vless:// یا vmess:// یا trojan:// یا ss:// شروع شود")
        if "\n" in link or " " in link:
            raise HTTPException(status_code=400, detail="هر بار فقط یک لینک وارد کن")
        item = {
            "id": secrets.token_hex(4),
            "kind": "custom",
            "label": body.label.strip() or link.split("://")[0].upper(),
            "link": link,
        }
    else:
        raise HTTPException(status_code=400, detail="نوع کانفیگ نامعتبر است")

    group["items"].append(item)
    save_db(data)
    return group


@app.delete("/admin/groups/{group_id}/items/{item_id}")
def delete_group_item(group_id: str, item_id: str, authorization: str | None = Header(default=None)):
    data, identity = require_identity(authorization)
    _require_root(identity)
    group = next((g for g in data["config_groups"] if g["id"] == group_id), None)
    if not group:
        raise HTTPException(status_code=404, detail="گروه پیدا نشد")
    group["items"] = [i for i in group["items"] if i["id"] != item_id]
    save_db(data)
    return group


# ==================== ادمین‌های فرعی ====================
# ادمین اصلی (root) می‌تونه ادمین‌های فرعی بسازه: هرکدوم یه رمز جدا دارن که
# باهاش وارد همین پنل می‌شن، یه سقف حجم کلی براشون تعیین می‌شه (مجموع حجم همه‌ی
# کانفیگ‌هایی که می‌سازن)، و وقتی وارد می‌شن فقط کانفیگ‌های خودشون رو می‌بینن
# و می‌تونن بسازن/ویرایش کنن. ادمین اصلی همچنان به همه‌ی کانفیگ‌های همه‌ی
# ادمین‌های فرعی هم دسترسی کامل داره (قطع/حذف/ریست از همون صفحه‌ی کاربرها).

@app.get("/admin/me")
def admin_me(authorization: str | None = Header(default=None)):
    """خودِ ادمین واردشده (اصلی یا فرعی) اطلاعات نقش و سقف حجم خودش رو می‌گیره."""
    data, identity = require_identity(authorization)
    if identity["role"] == "root":
        return {"role": "root", "username": "admin", "data_limit_bytes": 0, "used_traffic_bytes": 0}
    admin = next((a for a in data.get("admins", []) if a["username"] == identity["username"]), None)
    if not admin:
        raise HTTPException(status_code=404, detail="ادمین پیدا نشد")
    return {
        "role": "admin",
        "username": admin["username"],
        "data_limit_bytes": admin.get("data_limit_bytes") or 0,
        "used_traffic_bytes": xray_manager.admin_used_bytes(data, admin["username"]),
        "is_active": admin.get("is_active", True),
    }


@app.get("/admin/admins")
def list_admins(authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    result = []
    for a in data.get("admins", []):
        result.append({
            "username": a["username"],
            "data_limit_bytes": a.get("data_limit_bytes") or 0,
            "used_traffic_bytes": xray_manager.admin_used_bytes(data, a["username"]),
            "user_count": sum(1 for u in data["users"] if u.get("created_by") == a["username"]),
            "is_active": a.get("is_active", True),
            "created_at": a.get("created_at"),
        })
    return result


@app.post("/admin/admins")
def create_admin(body: AdminCreateBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    username = (body.username or "").strip()
    if not username or username == "admin":
        raise HTTPException(status_code=400, detail="این نام کاربری مجاز نیست")
    if any(a["username"] == username for a in data.get("admins", [])):
        raise HTTPException(status_code=400, detail="این نام کاربری قبلاً استفاده شده")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="رمز باید حداقل ۴ کاراکتر باشد")
    admin = {
        "username": username,
        "password_hash": hash_password(body.password),
        "data_limit_bytes": int(body.data_limit_gb * (1024 ** 3)) if body.data_limit_gb else 0,
        "is_active": True,
        "active_token": None,
        "created_at": db.now_iso(),
    }
    data.setdefault("admins", []).append(admin)
    save_db(data)
    return {"ok": True, "username": username}


@app.patch("/admin/admins/{username}")
def update_admin(username: str, body: AdminUpdateBody, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    admin = next((a for a in data.get("admins", []) if a["username"] == username), None)
    if not admin:
        raise HTTPException(status_code=404, detail="ادمین پیدا نشد")

    if body.data_limit_gb is not None:
        admin["data_limit_bytes"] = int(body.data_limit_gb * (1024 ** 3)) if body.data_limit_gb else 0
    if body.is_active is not None:
        admin["is_active"] = body.is_active
        if not body.is_active:
            admin["active_token"] = None  # نشستش هم بسته بشه، مجبور به ورود دوباره بشه
    if body.new_password:
        if len(body.new_password) < 4:
            raise HTTPException(status_code=400, detail="رمز باید حداقل ۴ کاراکتر باشد")
        admin["password_hash"] = hash_password(body.new_password)
        admin["active_token"] = None
    if body.reset_usage:
        for u in data["users"]:
            if u.get("created_by") == username:
                u["used_traffic_bytes"] = 0
                u["traffic_baseline_bytes"] = 0
        # حجم باقی‌مونده از کانفیگ‌های قبلاً حذف‌شده‌ی این ادمین هم پاک بشه،
        # وگرنه با اینکه کانفیگ‌های فعلیش صفر شدن بازم روی سقفش حساب می‌شه
        admin["banked_used_bytes"] = 0

    # وضعیت کانفیگ‌های این ادمین رو فوراً با سقف/فعال‌بودنِ جدیدش هماهنگ کن
    xray_manager.enforce_limits(data)
    xray_manager.enforce_admin_quotas(data)
    save_db(data)
    _apply_and_restart_safe(data)
    return {"ok": True}


@app.delete("/admin/admins/{username}")
def delete_admin(username: str, authorization: str | None = Header(default=None)):
    data = require_admin(authorization)
    before = len(data.get("admins", []))
    data["admins"] = [a for a in data.get("admins", []) if a["username"] != username]
    if len(data["admins"]) == before:
        raise HTTPException(status_code=404, detail="ادمین پیدا نشد")
    # کانفیگ‌های همین ادمین هم حذف می‌شن (دیگه صاحبی ندارن)
    data["users"] = [u for u in data["users"] if u.get("created_by") != username]
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
        links = collect_user_links(user, data, domain)
        content = "\n".join(links)
        return PlainTextResponse(base64.b64encode(content.encode("utf-8")).decode("utf-8"))

    sub_url = f"https://{domain}/sub/{token}"
    # طرحی که ادمین اصلی از «پنل شخصی» انتخاب کرده برای همه‌ی کاربرها اعمال می‌شه
    return HTMLResponse(subpage.render_sub_page(user, data["settings"], sub_url))


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
        "sub_theme": subpage.normalize_theme(s.get("sub_theme")),
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
    if body.sub_theme is not None:
        if body.sub_theme not in subpage.THEMES:
            raise HTTPException(status_code=400, detail="طرح نامعتبر است")
        s["sub_theme"] = body.sub_theme
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


_RESTORE_SKIP_SETTINGS = {
    "admin_password_hash", "active_token",
    # آدرس و پورت TCP Proxy مخصوص هر پروژه‌ی ریلویه؛ مقدار قدیمی روی پروژه‌ی جدید غلطه
    "reality_external_host", "reality_external_port",
}


def _build_backup_payload(data):
    admins = []
    for a in data.get("admins", []):
        a = dict(a)
        a.pop("active_token", None)
        admins.append(a)
    return {
        "format": "speedpanel-backup",
        "version": 2,
        "users": data["users"],
        "settings": {k: v for k, v in data["settings"].items()
                      if k not in ("admin_password_hash", "active_token")},
        "config_groups": data.get("config_groups", []),
        "admins": admins,
        "plans": data.get("plans", []),
        "orders": data.get("orders", []),
        # مسیر مخفی کانفیگ‌ها؛ بدونش لینک‌های قبلی روی پنل جدید کار نمی‌کنن
        "ws_path": xray_manager.VLESS_WS_PATH,
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


@app.post("/admin/restore-full")
def restore_full(body: FullRestoreBody, request: Request, authorization: str | None = Header(default=None)):
    """بازگردانی کامل روی یه پنلِ تازه (مثلاً بعد از تموم‌شدن ۳۰ روز ریلوی و ساختن
    دوباره‌ی پروژه): همه‌چیز از بکاپ جایگزین می‌شه به‌جز رمز پنل و آدرس TCP Proxy.
    UUID و توکن ساب کاربرها و مسیر مخفی کانفیگ‌ها همون قبلی می‌مونن، پس کانفیگ‌های
    قبلی دوباره وصل می‌شن؛ فقط آدرس (دامنه‌ی) لینک ساب عوض می‌شه."""
    data = require_admin(authorization)

    users = []
    seen = set()
    for u in body.users:
        if not isinstance(u, dict) or not u.get("username") or u["username"] in seen:
            continue
        seen.add(u["username"])
        u.setdefault("uuid", str(uuidlib.uuid4()))
        u.setdefault("subscription_token", secrets.token_urlsafe(16))
        u.setdefault("used_traffic_bytes", 0)
        u["traffic_baseline_bytes"] = u.get("used_traffic_bytes", 0)
        u["_last_session_bytes"] = 0
        u.setdefault("is_active", True)
        u.setdefault("created_by", "root")
        users.append(u)
    if not users and not body.config_groups and not body.admins:
        raise HTTPException(status_code=400, detail="این فایل بکاپ معتبر نیست یا خالیه")
    data["users"] = users

    if body.settings:
        for k, v in body.settings.items():
            if k not in _RESTORE_SKIP_SETTINGS:
                data["settings"][k] = v
    if body.config_groups is not None:
        data["config_groups"] = [g for g in body.config_groups if isinstance(g, dict) and g.get("id")]
    if body.admins is not None:
        data["admins"] = [dict(a, active_token=None) for a in body.admins if isinstance(a, dict) and a.get("username")]
    if body.plans is not None:
        data["plans"] = body.plans
    if body.orders is not None:
        data["orders"] = body.orders
    db._migrate(data)

    warnings = []
    if body.ws_path:
        ok, msg = xray_manager.set_base_path(body.ws_path)
        if not ok:
            warnings.append(msg)

    # ربات تلگرام: وبهوک باید به دامنه‌ی جدید اشاره کنه
    tg = data["settings"].get("telegram") or {}
    host = request.headers.get("host")
    if tg.get("token") and host:
        try:
            wh = httpx.get(
                f"https://api.telegram.org/bot{tg['token']}/setWebhook",
                params={"url": f"https://{host}/telegram/webhook/{tg['token']}"}, timeout=10,
            )
            if not wh.json().get("ok"):
                warnings.append("وبهوک ربات تلگرام تنظیم نشد؛ از «پنل شخصی» دوباره وصلش کن")
        except Exception:
            warnings.append("ارتباط با تلگرام برای تنظیم وبهوک برقرار نشد؛ از «پنل شخصی» دوباره وصلش کن")

    save_db(data)
    _apply_and_restart_safe(data)

    base = f"https://{host}" if host else ""
    links = [{"username": u["username"], "url": f"{base}/sub/{u['subscription_token']}"} for u in users]
    return {"ok": True, "users": len(users), "links": links, "warnings": warnings}


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
    # ادمین‌های فرعی هم اجازه دارن این صفحه (داشبورد) رو ببینن؛ اطلاعات حساسی
    # توش نیست و فقط مشخصات خودِ سروره
    data, _identity = require_identity(authorization)
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
        "region": detect_server_region(data["settings"]),
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
            changed = xray_manager.enforce_admin_quotas(data) or changed
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
