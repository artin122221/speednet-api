---

<div align="center"><img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=170&color=0:050816,50:17104A,100:00E5FF&text=SPEED%20NET&fontColor=FFFFFF&fontSize=48&fontAlignY=40&desc=SYSTEM%20CONFIGURATION&descSize=15&descAlignY=62&animation=twinkling" alt="SPEED NET System Configuration" /><br><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=20&duration=1800&pause=500&color=00E5FF&center=true&vCenter=true&width=650&height=45&lines=03+%E2%80%A2+PERSISTENT+STORAGE;04+%E2%80%A2+DOMAIN+GENERATOR;05+%E2%80%A2+ADMIN+ACCESS;06+%E2%80%A2+CREATE+CONFIG;07+%E2%80%A2+READY+TO+CONNECT" alt="Animated Setup Steps" /><br><img src="https://img.shields.io/badge/03-STORAGE-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/04-DOMAIN-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/05-LOGIN-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/06-CONFIG-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/07-LAUNCH-00E5FF?style=for-the-badge" /><br><br>

"⚡ INITIALIZE • CONFIGURE • CONNECT ⚡"

راهنمای تکمیل راه‌اندازی پنل SPEED NET

</div>---

<div align="center">"03" — PERSISTENT STORAGE

💾 ایجاد فضای ذخیره‌سازی دائمی

</div>برای اینکه اطلاعات پنل پس از Restart یا Deploy مجدد باقی بمانند، باید یک Volume ایجاد و به سرویس صحیح متصل کنید.

مراحل انجام کار:

1. وارد پروژه خود در Railway شوید.
2. سرویس اصلی پنل را انتخاب کنید.
3. وارد بخش Volumes شوید.
4. یک Volume جدید بسازید.
5. مسیر زیر را دقیقاً به‌عنوان Mount Path وارد کنید:

/app/data

6. بررسی کنید Volume به همان سرویسی متصل شده باشد که پنل را اجرا می‌کند.
7. اگر Railway برای اعمال تنظیمات نیاز به Deploy مجدد دارد، آن را انجام دهید.
8. پس از بالا آمدن سرویس، لاگ‌ها را بررسی کنید تا خطای اتصال Volume وجود نداشته باشد.

<div align="center"><img src="https://img.shields.io/badge/STORAGE-PERSISTENT-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/MOUNT%20PATH-/app/data-7C4DFF?style=for-the-badge" /></div>«💡 نکته مهم: اتصال Volume به‌تنهایی کافی نیست. برنامه نیز باید اطلاعات موردنظر را در "/app/data" ذخیره کند. اگر پایگاه داده یا فایل‌های پنل در مسیر دیگری باشند، باید تنظیمات برنامه متناسب با آن اصلاح شوند.»

---

<div align="center">"04" — DOMAIN GENERATOR

🌐 ساخت دامنه عمومی پنل

</div>پس از استقرار پروژه، باید یک دامنه عمومی برای دسترسی به پنل ایجاد کنید.

مراحل انجام کار:

1. وارد پروژه خود در Railway شوید.
2. سرویس اصلی پنل را باز کنید.
3. وارد بخش Settings → Networking یا بخش مربوط به دامنه‌های عمومی شوید.
4. گزینه تولید دامنه عمومی را انتخاب کنید.
5. پورت عمومی را با توجه به تنظیمات واقعی سرویس روی مقدار زیر قرار دهید:

8080

6. دامنه ایجادشده را کپی کنید.
7. منتظر بمانید تا دامنه فعال شود و سرویس پاسخ دهد.

🔗 آدرس ورود به پنل:

مسیر زیر را با دامنه واقعی خود ترکیب کنید:

https://YOUR-DOMAIN/x7m2qp9z

به‌جای "YOUR-DOMAIN"، دامنه واقعی Railway خود را قرار دهید.

مثال نمایشی:

https://your-panel.example.com/x7m2qp9z

«⚠️ توجه: آدرس بالا صرفاً نمونه است. دامنه نمونه را باز نکنید؛ دامنه واقعی سرویس خودتان را جایگزین کنید. مسیر "/x7m2qp9z" نیز باید در برنامه یا پراکسی تعریف شده باشد.»

<div align="center"><img src="https://img.shields.io/badge/NETWORK-PUBLIC-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/PORT-8080-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/PROTOCOL-HTTPS-00E5FF?style=for-the-badge" /></div>🔧 اگر دامنه باز نشد:

- وضعیت Deploy را بررسی کنید.
- لاگ‌های سرویس را برای خطاهای زمان اجرا بررسی کنید.
- مطمئن شوید پورت عمومی و پورت مورد انتظار برنامه با تنظیمات پراکسی هماهنگ هستند.
- بررسی کنید گواهی HTTPS فعال شده باشد.
- مطمئن شوید مسیر پنل در برنامه وجود دارد.

---

<div align="center">"05" — ADMIN ACCESS

🔐 ورود امن به پنل مدیریت

</div>پس از فعال شدن دامنه، آدرس پنل را در مرورگر باز کنید.

مراحل ورود:

1. آدرس پنل را با مسیر تعیین‌شده باز کنید.
2. صفحه ورود را بررسی کنید.
3. نام کاربری و رمز عبوری را وارد کنید که برای نسخه نصب‌شده تعریف شده است.
4. پس از ورود، تنظیمات امنیتی حساب مدیر را بررسی کنید.

اگر پروژه واقعاً از اطلاعات ورود اولیه زیر استفاده می‌کند، می‌توانید از آن‌ها برای ورود اولیه استفاده کنید:

Username: admin
Password: admin

🛡️ هشدار امنیتی:

- اطلاعات بالا برای همه نسخه‌های پروژه معتبر نیست.
- اگر ورود انجام نشد، اطلاعات تعریف‌شده در کد یا تنظیمات پروژه را بررسی کنید.
- در صورت استفاده از رمز اولیه، آن را فوراً با رمز قوی و منحصربه‌فرد جایگزین کنید.
- رمز مدیر را در README عمومی، پیام‌های مشتریان یا فایل‌های قابل‌مشاهده منتشر نکنید.

<div align="center"><img src="https://img.shields.io/badge/ACCESS-ADMIN-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/SECURITY-PASSWORD%20PROTECTED-00E5FF?style=for-the-badge" /></div>---

<div align="center">"06" — CONFIGURATION

⚙️ ساخت کانفیگ جدید

</div>پس از ورود موفق به پنل مدیریت، می‌توانید کانفیگ جدید ایجاد کنید.

مراحل ساخت کانفیگ:

1. وارد بخش مدیریت کاربران یا ساخت کانفیگ شوید.
2. گزینه ایجاد مورد جدید را انتخاب کنید.
3. نام یا شناسه کاربر را وارد کنید.
4. حجم مجاز را تعیین کنید.
5. مدت اعتبار را مشخص کنید.
6. تنظیمات اتصال موردنیاز پروژه را بررسی کنید.
7. کانفیگ را ایجاد و اطلاعات آن را ذخیره کنید.
8. وضعیت کانفیگ، حجم و تاریخ انقضا را بررسی کنید.

<div align="center"><img src="https://img.shields.io/badge/CONFIG-CREATE-00E5FF?style=for-the-badge" />
<img src="https://img.shields.io/badge/QUOTA-CONTROLLED-7C4DFF?style=for-the-badge" />
<img src="https://img.shields.io/badge/EXPIRY-CONFIGURABLE-00E5FF?style=for-the-badge" /></div>«💎 نکته: گزینه‌ها و تنظیمات قابل‌دسترسی به قابلیت‌های واقعی پنل شما بستگی دارند. اگر نسخه پروژه از لینک اشتراک پشتیبانی می‌کند، پس از ایجاد کانفیگ، لینک مربوط به همان کاربر را از پنل دریافت کنید.»

---

<div align="center">"07" — READY TO CONNECT

🚀 بررسی نهایی و تحویل به مشتری

</div>پیش از ارسال کانفیگ برای مشتری، مراحل زیر را بررسی کنید:

- [ ] سرویس Railway در وضعیت Running باشد.
- [ ] دامنه عمومی به‌درستی باز شود.
- [ ] اتصال HTTPS فعال باشد.
- [ ] Volume به سرویس درست متصل شده باشد.
- [ ] اطلاعات ضروری پس از Restart باقی بمانند.
- [ ] کانفیگ در پنل با موفقیت ایجاد شده باشد.
- [ ] حجم و مدت اعتبار صحیح باشند.
- [ ] اتصال کانفیگ با کلاینت سازگار آزمایش شده باشد.
- [ ] لینک اشتراک متعلق به کاربر صحیح باشد.

📦 تحویل کانفیگ:

پس از بررسی موارد بالا، لینک اشتراک یا اطلاعات اتصال را از طریق روش مناسب و امن در اختیار مشتری قرار دهید.

اطلاعات ورود مدیر، کلیدهای خصوصی و تنظیمات محرمانه سرور را همراه کانفیگ مشتری ارسال نکنید.

---

<div align="center"><img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=24&duration=1800&pause=500&color=00E5FF&center=true&vCenter=true&width=650&height=55&lines=SPEED+NET+IS+READY;DEPLOYED+%E2%80%A2+CONFIGURED+%E2%80%A2+CONNECTED;YOUR+PANEL.+YOUR+CONTROL." alt="SPEED NET Deployment Complete" /><br><img src="https://img.shields.io/badge/SPEED%20NET-ULTIMATE%20EDITION-080B18?style=for-the-badge&logo=lightning&logoColor=00E5FF" />
<img src="https://img.shields.io/badge/DEPLOYMENT-RAILWAY-171923?style=for-the-badge&logo=railway&logoColor=FFFFFF" />
<img src="https://img.shields.io/badge/STATUS-READY%20TO%20CONNECT-00E5FF?style=for-the-badge" /><br><br>

"⚡ POWERED BY SPEED NET ⚡"

Deploy smarter. Configure faster. Stay in control.

</div>---
