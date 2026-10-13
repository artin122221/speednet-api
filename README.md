---

<div align="center"><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=24&duration=2000&pause=500&color=00E5FF&center=true&vCenter=true&width=700&height=55&lines=03+%E2%80%A2+PERSISTENT+STORAGE;04+%E2%80%A2+DOMAIN+GENERATOR;05+%E2%80%A2+PANEL+ACCESS;06+%E2%80%A2+CONFIGURATION;07+%E2%80%A2+READY+TO+CONNECT" alt="SPEED NET Setup Steps" />"⚡ INITIALIZE • CONFIGURE • CONNECT ⚡"

"STEP 03" → "STEP 04" → "STEP 05" → "STEP 06" → "STEP 07"

</div>---

<img src="https://img.shields.io/badge/03-PERSISTENT%20STORAGE-00E5FF?style=for-the-badge" />

💾 ساخت و اتصال Volume

برای حفظ اطلاعات پنل پس از Restart یا Deploy مجدد، مراحل زیر را انجام دهید:

1. وارد تنظیمات سرویس خود در Railway شوید.
2. به بخش Volumes بروید.
3. یک Volume جدید ایجاد کنید.
4. مقدار زیر را به‌عنوان Mount Path قرار دهید:

/app/data

5. Volume را به سرویس اصلی پنل متصل کنید.
6. در صورت نیاز، سرویس را مجدداً Deploy کنید.

<div align="center"><img src="https://img.shields.io/badge/STORAGE-PERSISTENT-00E5FF?style=flat-square" />
<img src="https://img.shields.io/badge/MOUNT%20PATH-/app/data-7C4DFF?style=flat-square" /></div>«💠 نکته: برنامه باید اطلاعاتی را که قرار است باقی بمانند، واقعاً در مسیر "/app/data" ذخیره کند. ساخت Volume به‌تنهایی محل ذخیره‌سازی برنامه را تغییر نمی‌دهد.»

---

<img src="https://img.shields.io/badge/04-DOMAIN%20GENERATOR-7C4DFF?style=for-the-badge" />

🌐 ساخت دامنه اختصاصی پنل

پس از آنلاین‌شدن سرویس، دامنه عمومی آن را تنظیم کنید.

1. وارد بخش تنظیمات سرویس در Railway شوید.
2. بخش Networking یا Public Networking را باز کنید.
3. از قسمت تولید دامنه، یک دامنه عمومی ایجاد کنید.
4. پورت عمومی سرویس را روی مقدار زیر قرار دهید:

8080

5. پس از فعال‌شدن دامنه، آدرس نهایی را بررسی کنید.

🔗 آدرس مسیر پنل:

https://<دامنه‌ی پنل اصلی>/x7m2qp9z

به‌جای "<دامنه‌ی پنل اصلی>"، دامنه واقعی سرویس خود را وارد کنید.

مثال ساختاری:

https://your-panel-domain.example/x7m2qp9z

«⚠️ مهم: پورت "8080" باید با پورت عمومی تنظیم‌شده در سرویس و تنظیمات برنامه سازگار باشد. اگر برنامه از قبل با تنظیمات دیگری اجرا می‌شود، بدون بررسی پیکربندی آن را تغییر ندهید. مسیر "/x7m2qp9z" نیز باید در برنامه یا پراکسی تعریف شده باشد.»

---

<img src="https://img.shields.io/badge/05-ADMIN%20ACCESS-00E5FF?style=for-the-badge" />

🔐 ورود به پنل مدیریت

پس از آماده‌شدن دامنه:

1. آدرس پنل را در مرورگر باز کنید.
2. تا نمایش صفحه ورود منتظر بمانید.
3. با اطلاعات ورود اولیه‌ای که برنامه تعریف کرده است، وارد شوید.

در صورتی که نسخه پروژه از اطلاعات ورود پیش‌فرض زیر استفاده می‌کند:

Username: admin
Password: admin

از آن فقط برای ورود اولیه استفاده کنید و پیش از استفاده عمومی، رمز عبور را به یک رمز قوی و منحصربه‌فرد تغییر دهید.

«🛡️ اگر پروژه رمز اولیه متفاوتی دارد، از اطلاعات تعریف‌شده در تنظیمات یا مستندات همان نسخه استفاده کنید؛ نام کاربری و رمز بالا برای همه پروژه‌ها یکسان نیستند.»

---

<img src="https://img.shields.io/badge/06-CONFIGURATION-7C4DFF?style=for-the-badge" />

⚙️ ساخت کانفیگ جدید

پس از ورود موفق به پنل مدیریت:

1. به بخش ساخت کانفیگ یا مدیریت کاربران بروید.
2. گزینه ایجاد کانفیگ جدید را انتخاب کنید.
3. نام کاربر یا کانفیگ را وارد کنید.
4. حجم، مدت اعتبار و سایر تنظیمات موردنیاز را تعیین کنید.
5. تنظیمات را بررسی و کانفیگ را ایجاد کنید.
6. وضعیت کانفیگ و امکان اتصال آن را بررسی کنید.

<div align="center"><img src="https://img.shields.io/badge/CREATE-CONFIG-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/CONTROL-ADMIN%20ONLY-7C4DFF?style=for-the-badge" /></div>«💎 مقادیر قابل‌تنظیم به امکانات واقعی نسخه نصب‌شده بستگی دارند.»

---

<img src="https://img.shields.io/badge/07-READY%20TO%20CONNECT-00E5FF?style=for-the-badge" />

🚀 بررسی نهایی و تحویل به مشتری

پیش از تحویل کانفیگ، موارد زیر را بررسی کنید:

- سرویس پنل آنلاین باشد.
- دامنه با HTTPS باز شود.
- اطلاعات پنل پس از Restart باقی بمانند.
- کانفیگ ساخته‌شده معتبر باشد.
- حجم و مدت اعتبار درست تنظیم شده باشند.
- اتصال کانفیگ در کلاینت موردنظر آزمایش شده باشد.

پس از تأیید نهایی، لینک اشتراک یا اطلاعات اتصال را از طریق روش امن در اختیار مشتری قرار دهید.

<div align="center"><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=22&duration=1800&pause=500&color=00E5FF&center=true&vCenter=true&width=650&height=50&lines=SPEED+NET+IS+READY;YOUR+PANEL.+YOUR+CONTROL.;NEXT+GENERATION+CONNECTION" alt="SPEED NET Ready" /><img src="https://img.shields.io/badge/SPEED%20NET-DEPLOYED-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/STATUS-READY-7C4DFF?style=for-the-badge" />"⚡ POWERED BY SPEED NET ⚡"

Deploy smarter. Configure faster. Stay in control.

</div>---
