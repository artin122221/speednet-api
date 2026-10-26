#!/bin/sh
set -e

# پورت همیشه 8080 ثابته (همونی که توی Railway زیر Networking روی دامنه‌ی
# عمومی تنظیم شده). قبلاً این عدد رو از متغیر PORT می‌گرفتیم، ولی یه بار یه
# متغیر PORT با مقدار اشتباه (نه از طرف ما) باعث شد nginx رو یه پورت دیگه بالا
# بیاد و "Application failed to respond" بده. برای اینکه دیگه هیچ متغیر
# بیرونی نتونه این رو خراب کنه، همیشه همین مقدار ثابت استفاده می‌شه.
export PORT="8080"

# ---------------------------------------------------------------------------
# پوشه‌ی داده (دیتابیس، مسیر مخفی، کانفیگ Xray): بعضی هاست‌ها (مثل Hostless)
# فایل‌سیستم اصلی رو فقط‌خواندنی می‌کنن. پس اول یه جای قابل‌نوشتن پیدا می‌کنیم:
#   ۱) DATA_DIR (اگه خودت توی متغیرها گذاشتی، مثلاً مسیر Volume)
#   ۲) /app/data   ۳) /data   ۴) /tmp/speed-data (موقت؛ با ری‌استارت پاک می‌شه)
# ---------------------------------------------------------------------------
pick_dir() {
  for d in "$@"; do
    [ -z "$d" ] && continue
    if mkdir -p "$d" 2>/dev/null && touch "$d/.w" 2>/dev/null; then
      rm -f "$d/.w"
      echo "$d"
      return 0
    fi
  done
  return 1
}

DATA_DIR="$(pick_dir "$DATA_DIR" /app/data /data /tmp/speed-data /dev/shm/speed-data)" || {
  echo "[start] خطا: هیچ پوشه‌ی قابل‌نوشتنی پیدا نشد"; exit 1; }
case "$DATA_DIR" in
  /tmp/*|/dev/shm/*) echo "[start] هشدار: دیسک دائمی نیست؛ با هر ری‌استارت کاربرها پاک می‌شن. بکاپ بگیر." ;;
esac
echo "[start] پوشه‌ی داده: $DATA_DIR"
mkdir -p "$DATA_DIR/xray"
export DB_PATH="$DATA_DIR/db.json"
export WS_PATH_FILE="$DATA_DIR/ws_path.txt"
export XRAY_CONFIG_PATH="$DATA_DIR/xray/config.json"

# nginx روی فایل‌سیستم فقط‌خواندنی نمی‌تونه تنظیمات و فایل موقت بنویسه
RUN_DIR="$(pick_dir /tmp/nginx-run /dev/shm/nginx-run)" || {
  echo "[start] خطا: برای nginx پوشه‌ی قابل‌نوشتن نیست"; exit 1; }
mkdir -p "$RUN_DIR/body" "$RUN_DIR/proxy" "$RUN_DIR/fastcgi" "$RUN_DIR/uwsgi" "$RUN_DIR/scgi"
chmod -R 1777 "$RUN_DIR" 2>/dev/null || true
export NGINX_RUN_DIR="$RUN_DIR"
export NGINX_CONF_OUT="$RUN_DIR/nginx.conf"

# مسیر مخفیِ WebSocket کانفیگ VLESS: بار اول تصادفی ساخته می‌شه و برای همیشه
# روی دیسک ذخیره می‌مونه (ری‌استارت‌های بعدی همون قبلی رو برمی‌دارن). مسیر
# قدیمی "/vless-ws" هم توی تنظیمات nginx پایین نگه داشته شده تا کانفیگ‌هایی
# که از قبل به کاربرها داده شده خراب نشن.
export VLESS_WS_PATH="$(python3 /app/app/gen_ws_path.py)"
echo "[start] مسیر مخفی کانفیگ: $VLESS_WS_PATH"

# مسیرهای ورودی‌های اضافه (VMess / Trojan / HTTPUpgrade / XHTTP) از روی همون مسیر ساخته می‌شن
export VMESS_WS_PATH="${VLESS_WS_PATH}-vm"
export TROJAN_WS_PATH="${VLESS_WS_PATH}-tj"
export HTTPUPGRADE_PATH="${VLESS_WS_PATH}-hu"
export XHTTP_PATH="${VLESS_WS_PATH}-xh"

echo "[start] در حال ساختن تنظیمات nginx برای پورت $PORT ..."
envsubst '${PORT} ${NGINX_RUN_DIR} ${VLESS_WS_PATH} ${VMESS_WS_PATH} ${TROJAN_WS_PATH} ${HTTPUPGRADE_PATH} ${XHTTP_PATH}' < /app/nginx.conf.template > "$NGINX_CONF_OUT"

echo "[start] در حال اجرای FastAPI (پنل + API) روی پورت داخلی 8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 &

echo "[start] در حال اجرای nginx روی پورت عمومی $PORT ..."
exec nginx -e /dev/stderr -c "$NGINX_CONF_OUT" -g "daemon off;"
