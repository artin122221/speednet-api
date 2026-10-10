#!/bin/sh
set -e

# پورت همیشه 8080 ثابته (همونی که توی Railway زیر Networking روی دامنه‌ی
# عمومی تنظیم شده). قبلاً این عدد رو از متغیر PORT می‌گرفتیم، ولی یه بار یه
# متغیر PORT با مقدار اشتباه (نه از طرف ما) باعث شد nginx رو یه پورت دیگه بالا
# بیاد و "Application failed to respond" بده. برای اینکه دیگه هیچ متغیر
# بیرونی نتونه این رو خراب کنه، همیشه همین مقدار ثابت استفاده می‌شه.
export PORT="8080"

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
