#!/bin/sh
set -e

# ریلوی خودش پورت رو با متغیر PORT مشخص می‌کنه؛ اگه نبود، 8080 پیش‌فرضه (برای تست لوکال)
export PORT="${PORT:-8080}"

# مسیر مخفیِ WebSocket کانفیگ VLESS: بار اول تصادفی ساخته می‌شه و برای همیشه
# روی دیسک ذخیره می‌مونه (ری‌استارت‌های بعدی همون قبلی رو برمی‌دارن). مسیر
# قدیمی "/vless-ws" هم توی تنظیمات nginx پایین نگه داشته شده تا کانفیگ‌هایی
# که از قبل به کاربرها داده شده خراب نشن.
export VLESS_WS_PATH="$(python3 /app/app/gen_ws_path.py)"
echo "[start] مسیر مخفی کانفیگ: $VLESS_WS_PATH"

echo "[start] در حال ساختن تنظیمات nginx برای پورت $PORT ..."
envsubst '${PORT} ${VLESS_WS_PATH}' < /app/nginx.conf.template > /etc/nginx/nginx.conf

echo "[start] در حال اجرای FastAPI (پنل + API) روی پورت داخلی 8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 &

echo "[start] در حال اجرای nginx روی پورت عمومی $PORT ..."
nginx -g "daemon off;"
