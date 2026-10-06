#!/bin/sh
set -e

# ریلوی خودش پورت رو با متغیر PORT مشخص می‌کنه؛ اگه نبود، 8080 پیش‌فرضه (برای تست لوکال)
export PORT="${PORT:-8080}"

echo "[start] در حال ساختن تنظیمات nginx برای پورت $PORT ..."
envsubst '${PORT}' < /app/nginx.conf.template > /etc/nginx/nginx.conf

echo "[start] در حال اجرای FastAPI (پنل + API) روی پورت داخلی 8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 &

echo "[start] در حال اجرای nginx روی پورت عمومی $PORT ..."
nginx -g "daemon off;"
