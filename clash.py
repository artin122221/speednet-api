"""
ساخت خروجی‌های اشتراک اضافه:
  - کانفیگ‌های «اطلاعاتی» (حجم و روز باقی‌مانده) که بالای لیست اپ نشون داده می‌شن
  - خروجی Clash / Clash Meta (Mihomo) از روی همون لینک‌های کاربر
این فایل به FastAPI وابسته نیست، پس مستقل قابل تست‌ه.
"""
import base64
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, unquote, urlsplit

GB = 1024 ** 3
_FAKE_UUID = "00000000-0000-0000-0000-000000000000"


def info_remarks(user, now=None):
    """متن‌های کوتاهی که به‌صورت ردیف جدا بالای لیست کانفیگ‌ها میاد."""
    now = now or datetime.now(timezone.utc)
    used = user.get("used_traffic_bytes", 0) or 0
    limit = user.get("data_limit_bytes", 0) or 0
    out = []
    if user.get("on_hold"):
        out.append("⏸ در انتظار اولین اتصال")
    if limit:
        left = max(0, limit - used)
        out.append(f"📊 باقی‌مانده: {left / GB:.1f} GB از {limit / GB:.0f} GB")
    else:
        out.append(f"📊 مصرف: {used / GB:.1f} GB (نامحدود)")
    if user.get("expire_at"):
        try:
            secs = (datetime.fromisoformat(user["expire_at"]) - now).total_seconds()
            days = int(secs // 86400) + (1 if secs % 86400 > 0 else 0)
            out.append("⌛ منقضی شده" if secs <= 0 else f"⏳ {days} روز مانده")
        except ValueError:
            pass
    elif not user.get("on_hold"):
        out.append("⏳ بدون انقضا")
    return out


def info_links(user, now=None):
    return [
        f"vless://{_FAKE_UUID}@127.0.0.1:1?encryption=none&security=none&type=tcp#{quote(t)}"
        for t in info_remarks(user, now)
    ]


# ---------------------------------------------------------------- Clash ----

def _qs(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query, keep_blank_values=True).items()}


def _tls_common(p, q, default_sni):
    p["tls"] = True
    p["servername"] = q.get("sni") or q.get("host") or default_sni
    if q.get("fp"):
        p["client-fingerprint"] = q["fp"]
    p["skip-cert-verify"] = False


def link_to_clash(link):
    """یه لینک vless/vmess/trojan رو به یه پروکسی Clash Meta تبدیل می‌کنه.
    اگه پشتیبانی نشه (مثلاً XHTTP) None برمی‌گردونه."""
    link = (link or "").strip()
    try:
        if link.startswith("vmess://"):
            raw = link[8:]
            raw += "=" * (-len(raw) % 4)
            o = json.loads(base64.b64decode(raw).decode("utf-8"))
            p = {
                "name": o.get("ps") or "vmess", "type": "vmess", "server": o["add"],
                "port": int(o["port"]), "uuid": o["id"], "alterId": int(o.get("aid") or 0),
                "cipher": o.get("scy") or "auto", "udp": True,
            }
            if o.get("tls") == "tls":
                p["tls"] = True
                p["servername"] = o.get("sni") or o.get("host") or o["add"]
                if o.get("fp"):
                    p["client-fingerprint"] = o["fp"]
            if o.get("net") == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": o.get("path") or "/", "headers": {"Host": o.get("host") or o["add"]}}
            elif o.get("net") not in (None, "", "tcp"):
                return None
            return p

        u = urlsplit(link)
        if u.scheme not in ("vless", "trojan") or not u.hostname or not u.port:
            return None
        q = _qs(link)
        net = q.get("type") or "tcp"
        name = unquote(u.fragment) or u.scheme
        p = {"name": name, "type": u.scheme, "server": u.hostname, "port": u.port, "udp": True}
        if u.scheme == "vless":
            p["uuid"] = unquote(u.username or "")
            if q.get("flow"):
                p["flow"] = q["flow"]
        else:
            p["password"] = unquote(u.username or "")
        sec = q.get("security")
        if sec == "reality":
            p["tls"] = True
            p["servername"] = q.get("sni") or u.hostname
            p["client-fingerprint"] = q.get("fp") or "chrome"
            p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
        elif sec == "tls":
            _tls_common(p, q, u.hostname)
            if q.get("alpn"):
                p["alpn"] = q["alpn"].split(",")
        if net == "ws":
            p["network"] = "ws"
            p["ws-opts"] = {"path": unquote(q.get("path") or "/"), "headers": {"Host": q.get("host") or u.hostname}}
        elif net == "httpupgrade":
            p["network"] = "ws"
            p["ws-opts"] = {
                "path": unquote(q.get("path") or "/"),
                "headers": {"Host": q.get("host") or u.hostname},
                "v2ray-http-upgrade": True,
                "v2ray-http-upgrade-fast-open": True,
            }
        elif net == "tcp":
            p["network"] = "tcp"
        else:
            return None  # xhttp و بقیه رو Clash پشتیبانی نمی‌کنه
        return p
    except Exception:
        return None


def _scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(v, ensure_ascii=False)  # JSON رشته‌ها، YAML معتبره


def _emit(obj, indent=0):
    pad = "  " * indent
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines.extend(_emit(v, indent + 1))
            elif isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    else:
        for item in obj:
            if isinstance(item, dict):
                sub = _emit(item, indent + 1)
                first = sub[0].lstrip()
                lines.append(f"{pad}- {first}")
                lines.extend(sub[1:])
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return lines


def build_clash_yaml(links, group_name="Speed X4G"):
    proxies, seen = [], set()
    for link in links:
        p = link_to_clash(link)
        if not p:
            continue
        base, n = p["name"], 2
        while p["name"] in seen:
            p["name"] = f"{base} {n}"
            n += 1
        seen.add(p["name"])
        proxies.append(p)
    if not proxies:
        return None
    names = [p["name"] for p in proxies]
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "proxies": proxies,
        "proxy-groups": [
            {"name": group_name, "type": "select", "proxies": ["⚡ Auto"] + names + ["DIRECT"]},
            {"name": "⚡ Auto", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
        ],
        "rules": [
            "DOMAIN-SUFFIX,ir,DIRECT",
            f"MATCH,{group_name}",
        ],
    }
    return "\n".join(_emit(cfg)) + "\n"
