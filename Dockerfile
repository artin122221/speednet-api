FROM python:3.11-slim

# nginx: جلوی در، هم پنل هم ترافیک VPN رو مسیریابی می‌کنه
# curl/unzip: برای دانلود باینری واقعی Xray-core
# gettext-base: برای envsubst (جایگزینی $PORT توی تنظیمات nginx)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx curl unzip gettext-base ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# دانلود آخرین نسخه‌ی پایدار Xray-core (باینری رسمی از گیت‌هاب XTLS)
RUN curl -L -o /tmp/xray.zip \
    https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip /tmp/xray.zip -d /tmp/xray \
    && mv /tmp/xray/xray /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -rf /tmp/xray /tmp/xray.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY xray ./xray
COPY nginx.conf.template .
COPY start.sh .
RUN chmod +x start.sh

ENV DB_PATH=/app/data/db.json
ENV XRAY_BIN=/usr/local/bin/xray
ENV XRAY_CONFIG_PATH=/app/xray/config.json

EXPOSE 8080

CMD ["./start.sh"]
