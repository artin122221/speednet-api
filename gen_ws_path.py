"""
این اسکریپت قبل از بالا اومدن nginx و FastAPI اجرا می‌شه (از start.sh صدا زده
می‌شه) و یه مسیر مخفی و تصادفی برای WebSocket کانفیگ VLESS می‌سازه، به‌جای
مسیر ثابت و قابل‌حدس "/vless-ws" که قبلاً همیشه یکی بود.

نکته‌ی خیلی مهم: این مسیر فقط "بار اول" تصادفی ساخته می‌شه و بعدش روی دیسک
(کنار db.json، توی همون پوشه‌ی دائمی) ذخیره می‌مونه. دفعات بعد که سرور بالا
میاد، همون مسیر قبلی رو برمی‌گردونه، نه یه مسیر جدید — وگرنه هر ری‌استارت
همه‌ی کانفیگ‌های جدید رو خراب می‌کرد.

کانفیگ‌هایی که از قبل (با مسیر قدیمیِ "/vless-ws") به کاربرها داده شده، همچنان
کار می‌کنن چون nginx.conf.template یه ورودی جدا برای مسیر قدیمی هم داره که
به همین مسیر جدید وصل می‌شه؛ فقط کانفیگ‌های جدیدی که از این به بعد ساخته
می‌شن از مسیر مخفی‌تر استفاده می‌کنن.
"""
import os
import secrets

WS_PATH_FILE = os.environ.get("WS_PATH_FILE", "/app/data/ws_path.txt")


def main():
    os.makedirs(os.path.dirname(WS_PATH_FILE), exist_ok=True)

    if os.path.exists(WS_PATH_FILE):
        with open(WS_PATH_FILE, "r", encoding="utf-8") as f:
            existing = f.read().strip()
        if existing.startswith("/") and len(existing) > 1:
            print(existing)
            return

    new_path = "/" + secrets.token_urlsafe(9)
    tmp_path = WS_PATH_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(new_path)
    os.replace(tmp_path, WS_PATH_FILE)
    print(new_path)


if __name__ == "__main__":
    main()
