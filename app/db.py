"""
دیتابیس خیلی ساده‌ی مبتنی بر فایل JSON.
برای یه پنل کوچیک، فایل JSON کاملاً کافیه و دیباگش هم راحته
(می‌تونی مستقیم فایل data/db.json رو باز کنی و ببینی چی توشه).
"""
import json
import os
import secrets
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/app/data/db.json")
_lock = threading.Lock()

DEFAULT_SERVICE_CATALOG = [
    {"id": "youtube", "label": "یوتیوب", "domains": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"]},
    {"id": "instagram", "label": "اینستاگرام", "domains": ["instagram.com", "cdninstagram.com", "fbcdn.net"]},
    {"id": "telegram", "label": "تلگرام", "domains": ["telegram.org", "t.me", "telesco.pe"]},
    {"id": "whatsapp", "label": "واتس‌اپ", "domains": ["whatsapp.com", "whatsapp.net"]},
    {"id": "twitter", "label": "توییتر/X", "domains": ["twitter.com", "x.com", "twimg.com"]},
    {"id": "facebook", "label": "فیسبوک", "domains": ["facebook.com", "fbcdn.net"]},
    {"id": "tiktok", "label": "تیک‌تاک", "domains": ["tiktok.com", "tiktokcdn.com"]},
    {"id": "netflix", "label": "نتفلیکس", "domains": ["netflix.com", "nflxvideo.net"]},
]


def _default_db():
    return {
        # شناسه‌ی یکتای همین نصب پنل — فقط برای معرفی خودش به سرور آپدیت مرکزی استفاده می‌شه
        "instance_id": secrets.token_hex(8),
        "settings": {
            # رمز پیش‌فرض اولیه: admin — حتماً بعد از اولین ورود از داخل پنل عوضش کن
            "admin_password_hash": None,
            "active_token": None,
            "brand_name": "Speed Panel",
            "support_telegram": "Config_v2rey_ir",
            "server_region": "Frankfurt",
            "server_host_name": "Railway",
            "latest_version": "1.0",
            "update_message": "",
            "blocked_domains": "",
            "blocked_services": [],
            "telegram": {"connected": False, "token": None, "username": None},
        },
        "users": [],
    }


def _ensure_dir():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def load():
    _ensure_dir()
    if not os.path.exists(DB_PATH):
        data = _default_db()
        save(data)
        return data
    with _lock:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)


def save(data):
    _ensure_dir()
    with _lock:
        tmp_path = DB_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, DB_PATH)


def now_iso():
    return datetime.now(timezone.utc).isoformat()
