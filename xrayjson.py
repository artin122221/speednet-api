"""ساخت کانفیگ کامل Xray (JSON) برای کلاینت‌هایی که فرگمنت (Fragment) و Mux
رو پشتیبانی می‌کنن (مثل v2rayNG و v2rayN). این‌ها تنظیمات سمت کلاینت هستن،
پس فقط توی خروجی ساب با فرمت ?format=xray میان، نه توی لینک‌های معمولی."""
import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

DEFAULTS = {
    "fragment": False,
    "packets": "tlshello",
    "length": "10-20",
    "interval": "10-20",
    "mux": False,
    "mux_concurrency": 8,
    "fp": "",   # خالی = اثر انگشتِ خودِ لینک
    "auto_best": True,   # چند حالت + حالت خودکار (برای همه‌ی اینترنت‌ها)
}
FP_ALLOWED = ("", "chrome", "firefox", "safari", "ios", "android", "edge", "randomized", "random")
_RANGE_RE = re.compile(r"^\d{1,4}(-\d{1,4})?$")
_PACKETS_RE = re.compile(r"^(tlshello|\d{1}(-\d{1})?)$")


def get_settings(data):
    cfg = dict(DEFAULTS)
    cfg.update(data.get("settings", {}).get("antifilter") or {})
    return cfg


def clean(body):
    """ورودی ادمین رو چک و تمیز می‌کنه؛ مقدار نامعتبر → ValueError."""
    out = {}
    if body.get("fragment") is not None:
        out["fragment"] = bool(body["fragment"])
    if body.get("mux") is not None:
        out["mux"] = bool(body["mux"])
    if body.get("auto_best") is not None:
        out["auto_best"] = bool(body["auto_best"])
    if body.get("packets") not in (None, ""):
        if not _PACKETS_RE.match(str(body["packets"])):
            raise ValueError("مقدار «بسته‌ها» نامعتبره (مثلاً tlshello)")
        out["packets"] = str(body["packets"])
    for key, label in (("length", "طول"), ("interval", "فاصله")):
        if body.get(key) not in (None, ""):
            if not _RANGE_RE.match(str(body[key])):
                raise ValueError(f"مقدار «{label}» نامعتبره (مثلاً 10-20)")
            out[key] = str(body[key])
    if body.get("fp") is not None:
        if body["fp"] not in FP_ALLOWED:
            raise ValueError("اثر انگشت TLS نامعتبره")
        out["fp"] = body["fp"]
    if body.get("mux_concurrency") not in (None, ""):
        c = int(body["mux_concurrency"])
        if not 1 <= c <= 16:
            raise ValueError("تعداد هم‌زمانی Mux باید بین ۱ تا ۱۶ باشه")
        out["mux_concurrency"] = c
    return out


def _qs(link):
    return {k: v[0] for k, v in parse_qs(urlsplit(link).query, keep_blank_values=True).items()}


def _stream(q, host, cfg, frag_tag=None):
    net = q.get("type") or "tcp"
    sec = q.get("security") or "none"
    s = {"network": net, "security": sec}
    sni = q.get("sni") or q.get("host") or host
    fp = cfg.get("fp") or q.get("fp") or "chrome"
    if sec == "tls":
        s["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "allowInsecure": False}
        if q.get("alpn"):
            s["tlsSettings"]["alpn"] = q["alpn"].split(",")
    elif sec == "reality":
        s["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""), "spiderX": "",
        }
    path = unquote(q.get("path") or "/")
    hdr_host = q.get("host") or host
    if net == "ws":
        s["wsSettings"] = {"path": path, "headers": {"Host": hdr_host}}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path, "host": hdr_host}
    elif net == "xhttp":
        s["xhttpSettings"] = {"path": path, "host": hdr_host, "mode": q.get("mode") or "auto"}
    elif net not in ("tcp",):
        return None
    if frag_tag and sec in ("tls", "reality"):
        s["sockopt"] = {"dialerProxy": frag_tag}
    return s


def link_to_outbound(link, cfg, tag="proxy", frag_tag=None):
    """(نام، outbound) یا None اگه لینک پشتیبانی نشه."""
    link = (link or "").strip()
    try:
        if link.startswith("vmess://"):
            raw = link[8:]
            raw += "=" * (-len(raw) % 4)
            o = json.loads(base64.b64decode(raw).decode("utf-8"))
            q = {"type": o.get("net") or "tcp", "security": "tls" if o.get("tls") == "tls" else "none",
                 "sni": o.get("sni") or o.get("host") or "", "host": o.get("host") or "",
                 "path": o.get("path") or "/", "fp": o.get("fp") or "chrome", "alpn": o.get("alpn") or ""}
            st = _stream(q, o["add"], cfg, frag_tag)
            if st is None:
                return None
            ob = {"tag": tag, "protocol": "vmess", "settings": {"vnext": [{
                "address": o["add"], "port": int(o["port"]),
                "users": [{"id": o["id"], "alterId": int(o.get("aid") or 0), "security": o.get("scy") or "auto"}]}]},
                "streamSettings": st}
            name = o.get("ps") or "vmess"
        else:
            u = urlsplit(link)
            if u.scheme not in ("vless", "trojan") or not u.hostname or not u.port:
                return None
            q = _qs(link)
            st = _stream(q, u.hostname, cfg, frag_tag)
            if st is None:
                return None
            name = unquote(u.fragment) or u.scheme
            if u.scheme == "vless":
                user = {"id": unquote(u.username or ""), "encryption": "none"}
                if q.get("flow"):
                    user["flow"] = q["flow"]
                ob = {"tag": tag, "protocol": "vless",
                      "settings": {"vnext": [{"address": u.hostname, "port": u.port, "users": [user]}]},
                      "streamSettings": st}
            else:
                ob = {"tag": tag, "protocol": "trojan",
                      "settings": {"servers": [{"address": u.hostname, "port": u.port, "password": unquote(u.username or "")}]},
                      "streamSettings": st}
        flow = (q.get("flow") if not link.startswith("vmess://") else "") or ""
        net = st.get("network")
        # Mux با flow (Vision) و XHTTP سازگار نیست
        if cfg["mux"] and not flow and net != "xhttp":
            ob["mux"] = {"enabled": True, "concurrency": int(cfg["mux_concurrency"])}
        return name, ob
    except Exception:
        return None


def _frag_outbound(tag, packets, length, interval):
    return {
        "tag": tag, "protocol": "freedom",
        "settings": {"fragment": {"packets": packets, "length": length, "interval": interval}},
        "streamSettings": {"sockopt": {"tcpNoDelay": True}},
    }


def _variants(cfg):
    """حالت‌های اتصال: (برچسب، تنظیم فرگمنت یا None). اگه ادمین Fragment رو روشن
    کرده باشه، مقدار خودش اولویت داره؛ وگرنه ساده + دو حالت فرگمنت پیشنهادی."""
    if cfg["fragment"]:
        v = [("Fragment", (cfg["packets"], cfg["length"], cfg["interval"])), ("ساده", None)]
    elif cfg.get("auto_best", True):
        v = [("ساده", None), ("Fragment A", ("tlshello", "100-200", "10-20")),
             ("Fragment B", ("tlshello", "10-30", "10-20"))]
    else:
        v = [("ساده", None)]
    return v


def _base(name):
    return {
        "remarks": name,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}, "settings": {"auth": "noauth", "udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"},
        ],
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
    }


def build_json(links, cfg):
    """برای هر لینک چند حالت می‌سازه + یه کانفیگ «خودکار» که بین همه‌ی حالت‌ها
    سریع‌ترین رو خودش انتخاب می‌کنه (برای شبکه‌های مختلف)."""
    configs = []
    auto_outs, auto_frags = [], {}
    variants = _variants(cfg)
    multi = len(variants) > 1
    for link in links:
        for vi, (label, frag) in enumerate(variants):
            ftag = None
            if frag:
                ftag = "frag-%d" % vi
            r = link_to_outbound(link, cfg, tag="proxy", frag_tag=ftag)
            if not r:
                continue
            name, ob = r
            if frag and "sockopt" not in ob["streamSettings"]:
                continue   # فرگمنت فقط برای TLS/REALITY معنی داره
            c = _base(name + (" (%s)" % label if multi else ""))
            outs = [ob]
            if frag:
                outs.append(_frag_outbound(ftag, *frag))
            outs += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
            c["outbounds"] = outs
            c["routing"] = {"domainStrategy": "AsIs", "rules": [{"type": "field", "port": "0-65535", "outboundTag": "proxy"}]}
            configs.append(c)
            # برای حالت خودکار
            aid = "px-%d" % len(auto_outs)
            r2 = link_to_outbound(link, cfg, tag=aid, frag_tag=("frag-%d" % vi) if frag else None)
            if r2:
                auto_outs.append(r2[1])
                if frag:
                    auto_frags["frag-%d" % vi] = frag
    if cfg.get("auto_best", True) and len(auto_outs) > 1:
        a = _base("⚡ خودکار (بهترین اتصال)")
        outs = list(auto_outs)
        for t, f in auto_frags.items():
            outs.append(_frag_outbound(t, *f))
        outs += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
        a["outbounds"] = outs
        a["observatory"] = {"subjectSelector": ["px-"], "probeUrl": "https://www.gstatic.com/generate_204",
                            "probeInterval": "60s", "enableConcurrency": True}
        a["routing"] = {
            "domainStrategy": "AsIs",
            "balancers": [{"tag": "auto", "selector": ["px-"], "strategy": {"type": "leastPing"}, "fallbackTag": "px-0"}],
            "rules": [{"type": "field", "port": "0-65535", "balancerTag": "auto"}],
        }
        configs.insert(0, a)
    return json.dumps(configs, ensure_ascii=False, indent=2) if configs else ""
