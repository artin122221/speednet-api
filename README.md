<div align="center"><img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=200&color=0:050816,35:17104A,70:075985,100:00E5FF&text=SPEED%20NET&fontColor=FFFFFF&fontSize=55&fontAlignY=38&desc=NEXT%20GENERATION%20PANEL&descSize=17&descAlignY=58&animation=twinkling&stroke=00E5FF&strokeWidth=1" alt="SPEED NET" /><br><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=22&duration=2000&pause=500&color=00E5FF&center=true&vCenter=true&width=650&height=50&lines=INITIALIZE+%E2%80%A2+CONFIGURE+%E2%80%A2+CONNECT;YOUR+PANEL.+YOUR+CONTROL.;WELCOME+TO+SPEED+NET" alt="SPEED NET Animated Title" /><br><img src="https://img.shields.io/badge/03-STORAGE-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/04-DOMAIN-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/05-ADMIN-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/06-CONFIG-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/07-LAUNCH-00E5FF?style=for-the-badge" /><br><br>

"⚡ SYSTEM INITIALIZATION ⚡"

راهنمای راه‌اندازی و استفاده از پنل SPEED NET

</div>---

<div align="center">"03" — PERSISTENT STORAGE

💾 ساخت و اتصال Volume

</div>برای ایجاد فضای ذخیره‌سازی در Railway مراحل زیر را انجام دهید:

1. وارد پروژه خود در Railway شوید.
2. سرویس اصلی پنل را انتخاب کنید.
3. وارد بخش Volumes شوید.
4. یک Volume جدید ایجاد کنید.
5. مقدار زیر را به‌عنوان Mount Path وارد کنید:

/app/data

6. Volume را به سرویس اصلی پنل متصل کنید.
7. در صورت نیاز، سرویس را مجدداً Deploy کنید.
8. لاگ‌های سرویس را بررسی کنید تا اجرای برنامه با موفقیت انجام شده باشد.

<div align="center"><img src="https://img.shields.io/badge/STORAGE-PERSISTENT-00E5FF?style=flat-square" />
<img src="https://img.shields.io/badge/MOUNT%20PATH-/app/data-7C4DFF?style=flat-square" /></div>---

<div align="center">"04" — DOMAIN GENERATOR

🌐 ساخت دامنه عمومی پنل

</div>برای دسترسی به پنل از طریق دامنه عمومی:

1. وارد پروژه خود در Railway شوید.
2. سرویس اصلی پنل را باز کنید.
3. وارد بخش Settings → Networking شوید.
4. گزینه تولید دامنه عمومی را انتخاب کنید.
5. پورت عمومی را مطابق تنظیمات واقعی سرویس روی "8080" قرار دهید.
6. دامنه ایجادشده را کپی کنید.
7. منتظر بمانید تا دامنه فعال شود.

🔗 آدرس ورود به پنل:

https://YOUR-DOMAIN/x7m2qp9z

به‌جای "YOUR-DOMAIN"، دامنه واقعی پنل خود را قرار دهید.

<div align="center"><img src="https://img.shields.io/badge/NETWORK-PUBLIC-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/PORT-8080-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/PROTOCOL-HTTPS-00E5FF?style=for-the-badge" /></div>اگر دامنه باز نشد:

- وضعیت Deploy را بررسی کنید.
- لاگ‌های Railway را بررسی کنید.
- مطمئن شوید پورت عمومی با تنظیمات سرویس هماهنگ است.
- فعال بودن HTTPS و تعریف مسیر "/x7m2qp9z" را بررسی کنید.

---

<div align="center">"05" — ADMIN ACCESS

🔐 ورود به پنل مدیریت

</div>پس از فعال‌شدن دامنه:

1. آدرس پنل را در مرورگر باز کنید.
2. صفحه ورود را مشاهده کنید.
3. نام کاربری و رمز عبور تعریف‌شده برای نسخه نصب‌شده را وارد کنید.
4. پس از ورود موفق، تنظیمات امنیتی حساب مدیر را بررسی کنید.

اگر نسخه پروژه از اطلاعات ورود اولیه زیر استفاده می‌کند:

Username: admin
Password: admin

پس از ورود، رمز عبور را به یک رمز قوی و منحصربه‌فرد تغییر دهید.

<div align="center"><img src="https://img.shields.io/badge/ACCESS-ADMIN-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/SECURITY-PROTECTED-00E5FF?style=for-the-badge" /></div>---

<div align="center">"06" — CONFIGURATION

⚙️ ساخت کانفیگ جدید

</div>پس از ورود به پنل مدیریت:

1. وارد بخش مدیریت کاربران یا ساخت کانفیگ شوید.
2. گزینه ایجاد کانفیگ جدید را انتخاب کنید.
3. نام یا شناسه کاربر را وارد کنید.
4. حجم مجاز را تعیین کنید.
5. مدت اعتبار را مشخص کنید.
6. تنظیمات اتصال را بررسی کنید.
7. کانفیگ را ایجاد کنید.
8. وضعیت، حجم و تاریخ انقضای کانفیگ را بررسی کنید.

<div align="center"><img src="https://img.shields.io/badge/CONFIG-CREATE-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/QUOTA-CONTROLLED-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/EXPIRY-CONFIGURABLE-00E5FF?style=for-the-badge" /></div>اگر پنل از لینک اشتراک پشتیبانی می‌کند، پس از ساخت کانفیگ لینک مربوط به همان کاربر را دریافت کنید.

---

<div align="center">"07" — READY TO CONNECT

🚀 بررسی نهایی و تحویل به مشتری

</div>پیش از تحویل کانفیگ، موارد زیر را بررسی کنید:

- [ ] سرویس Railway در وضعیت Running باشد.
- [ ] دامنه عمومی به‌درستی باز شود.
- [ ] اتصال HTTPS فعال باشد.
- [ ] Volume به سرویس موردنظر متصل شده باشد.
- [ ] کانفیگ با موفقیت ایجاد شده باشد.
- [ ] حجم و مدت اعتبار صحیح باشند.
- [ ] اتصال کانفیگ با کلاینت سازگار آزمایش شده باشد.
- [ ] لینک اشتراک متعلق به کاربر صحیح باشد.

📦 تحویل کانفیگ به مشتری

پس از بررسی نهایی، لینک اشتراک یا اطلاعات اتصال را به روش امن در اختیار مشتری قرار دهید.

اطلاعات ورود مدیر و کلیدهای خصوصی سرور را برای مشتری ارسال نکنید.

---

<div align="center"><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=23&duration=1800&pause=500&color=00E5FF&center=true&vCenter=true&width=650&height=55&lines=SPEED+NET+IS+READY;DEPLOYED+%E2%80%A2+CONFIGURED+%E2%80%A2+CONNECTED;YOUR+PANEL.+YOUR+CONTROL." alt="SPEED NET Ready" /><br><img src="https://img.shields.io/badge/SPEED%20NET-ULTIMATE%20EDITION-080B18?style=for-the-badge&logo=lightning&logoColor=00E5FF" />
<img src="https://img.shields.io/badge/DEPLOYMENT-RAILWAY-171923?style=for-the-badge&logo=railway&logoColor=FFFFFF" />
<img src="https://img.shields.io/badge/STATUS-READY-00E5FF?style=for-the-badge" /><br><br>

"⚡ POWERED BY SPEED NET ⚡"

Deploy smarter. Configure faster. Stay in control.

</div>---
