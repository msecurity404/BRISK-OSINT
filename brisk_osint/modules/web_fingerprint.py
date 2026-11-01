"""Web surface: headers, cookies, TLS, technologies, robots/security.txt."""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone

from ..core import Context, Result, http, pmap

NAME = "web"
DESC = "HTTP security headers, cookies, TLS certificate, tech stack, robots/security.txt"
PHASE = 1

SEC_HEADERS = {
    "strict-transport-security": ("medium", "HSTS missing: browsers may connect over plain HTTP"),
    "content-security-policy": ("medium", "No Content-Security-Policy: weaker XSS mitigation"),
    "x-content-type-options": ("low", "X-Content-Type-Options missing (MIME sniffing)"),
    "referrer-policy": ("low", "Referrer-Policy missing"),
    "permissions-policy": ("info", "Permissions-Policy missing"),
}

TECH_SIGS = [
    ("WordPress", r"wp-content|wp-includes|wp-json"), ("Drupal", r"Drupal\.settings|sites/default/files"),
    ("Joomla", r"/media/jui/|Joomla!"), ("Shopify", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", r"wixstatic\.com"), ("Squarespace", r"squarespace\.com"), ("React", r"data-reactroot|__REACT"),
    ("Next.js", r"/_next/static|__NEXT_DATA__"), ("Vue.js", r"data-v-[0-9a-f]{6}|vue(\.min)?\.js"),
    ("Angular", r"ng-version|ng-app"), ("jQuery", r"jquery[-.\d]*(\.min)?\.js"),
    ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"), ("Google Analytics", r"google-analytics\.com|gtag\("),
    ("Google Tag Manager", r"googletagmanager\.com"), ("Cloudflare", r"cdnjs\.cloudflare\.com"),
    ("Stripe", r"js\.stripe\.com"), ("Intercom", r"widget\.intercom\.io"), ("Hotjar", r"static\.hotjar\.com"),
]
SENSITIVE_PROBES = ["/.git/HEAD", "/.env", "/.DS_Store", "/server-status", "/phpinfo.php",
                    "/backup.zip", "/wp-config.php.bak", "/.svn/entries", "/config.json", "/actuator/health"]
PROBE_MARKERS = {"/.git/HEAD": "ref:", "/.env": "=", "/server-status": "Apache Server Status",
                 "/phpinfo.php": "phpinfo()", "/.svn/entries": "dir", "/actuator/health": '"status"'}


def tls_info(host: str, timeout: int) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
                proto, cipher = t.version(), t.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        return {"error": f"certificate verification failed: {e.verify_message}"}
    except Exception as e:  # noqa: BLE001
        return None if "refused" in str(e).lower() or "timed out" in str(e).lower() else {"error": str(e)}
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subj = dict(x[0] for x in cert.get("subject", []))
    na = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return {"issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject": subj.get("commonName"), "not_after": na.isoformat(),
            "days_left": (na - datetime.now(timezone.utc)).days,
            "sans": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
            "protocol": proto, "cipher": cipher}


def run(ctx: Context) -> Result:
    res = Result(NAME)
    base = None
    for host in (ctx.target, f"www.{ctx.target}"):
        r = http(f"https://{host}/", timeout=ctx.timeout)
        if r["status"]:
            base = (host, r)
            break
    if not base:
        res.error = "No HTTPS response from apex or www"
        return res
    host, r = base
    h = r["headers"]
    res.data["host"] = host
    res.data["final_url"] = r["url"]
    res.data["status"] = r["status"]
    res.data["server"] = h.get("server")
    res.data["powered_by"] = h.get("x-powered-by")

    m = re.search(r"<title[^>]*>(.*?)</title>", r["text"], re.I | re.S)
    res.data["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:150] if m else None

    # security headers
    missing = []
    for hd, (sev, msg) in SEC_HEADERS.items():
        if hd not in h:
            missing.append(hd)
            res.add(sev, msg)
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("x-frame-options")
        res.add("low", "Clickjacking protection missing", "Set X-Frame-Options or CSP frame-ancestors")
    res.data["missing_headers"] = missing
    if h.get("server") and re.search(r"\d", h["server"]):
        res.add("low", "Server banner discloses version", h["server"])
    if h.get("x-powered-by"):
        res.add("low", "X-Powered-By discloses technology", h["x-powered-by"])

    # cookies
    cookies = []
    for c in r["cookies"]:
        name = c.split("=", 1)[0]
        flags = {"secure": "secure" in c.lower(), "httponly": "httponly" in c.lower(),
                 "samesite": "samesite" in c.lower()}
        cookies.append({"name": name, **flags})
        if not flags["secure"] or not flags["httponly"]:
            res.add("low", f"Cookie '{name}' missing Secure/HttpOnly",
                    f"secure={flags['secure']} httponly={flags['httponly']}")
    res.data["cookies"] = cookies

    # HTTP -> HTTPS
    plain = http(f"http://{host}/", timeout=ctx.timeout, retries=0)
    if plain["status"]:
        res.data["http_redirects_to_https"] = plain["url"].startswith("https://")
        if not plain["url"].startswith("https://"):
            res.add("high", "Site is reachable over plain HTTP without redirect", plain["url"])

    # TLS
    tls = tls_info(host, ctx.timeout)
    res.data["tls"] = tls
    if tls:
        if "error" in tls:
            res.add("high", "TLS problem", tls["error"])
        else:
            if tls["days_left"] < 0:
                res.add("critical", "TLS certificate has expired")
            elif tls["days_left"] < 15:
                res.add("high", "TLS certificate expires within 15 days", f"{tls['days_left']} days left")
            elif tls["days_left"] < 30:
                res.add("medium", "TLS certificate expires within 30 days", f"{tls['days_left']} days left")
            if tls["protocol"] in ("TLSv1", "TLSv1.1"):
                res.add("high", f"Weak TLS protocol negotiated: {tls['protocol']}")

    # technology detection
    tech = set()
    blob = r["text"][:400_000]
    for name, rx in TECH_SIGS:
        if re.search(rx, blob, re.I):
            tech.add(name)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', blob, re.I)
    if gen:
        tech.add(gen.group(1))
    if "cf-ray" in h or "cloudflare" in h.get("server", "").lower():
        tech.add("Cloudflare CDN/WAF")
    if "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower():
        tech.add("AWS CloudFront")
    if "x-vercel-id" in h:
        tech.add("Vercel")
    if "x-served-by" in h and "cache" in h.get("x-served-by", "").lower():
        tech.add("Fastly")
    if h.get("server"):
        tech.add(h["server"])
    res.data["technologies"] = sorted(tech)

    # well-known files
    base_url = f"https://{host}"
    sec = http(f"{base_url}/.well-known/security.txt", timeout=ctx.timeout, retries=0)
    res.data["security_txt"] = sec["status"] == 200 and "contact" in sec["text"].lower()
    if not res.data["security_txt"]:
        res.add("info", "No security.txt", "Publish /.well-known/security.txt so researchers can reach you")
    rob = http(f"{base_url}/robots.txt", timeout=ctx.timeout, retries=0)
    if rob["status"] == 200 and "text/html" not in rob["headers"].get("content-type", ""):
        dis = sorted({l.split(":", 1)[1].strip() for l in rob["text"].splitlines()
                      if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip() not in ("", "/")})
        res.data["robots_disallow"] = dis[:100]
        hot = [p for p in dis if re.search(r"admin|backup|private|internal|staging|test|login|config|secret", p, re.I)]
        if hot:
            res.add("info", "robots.txt reveals sensitive-looking paths", ", ".join(hot[:10]), hot)
        res.data["sitemaps"] = [l.split(":", 1)[1].strip() for l in rob["text"].splitlines()
                                if l.lower().startswith("sitemap:")][:10]

    # optional light exposure probes
    if ctx.active:
        def probe(path):
            p = http(base_url + path, timeout=ctx.timeout, retries=0, max_bytes=20_000)
            if p["status"] != 200:
                return None
            marker = PROBE_MARKERS.get(path)
            if marker:
                return path if marker in p["text"] else None
            # no marker: accept only non-HTML responses (avoids soft-404 pages)
            return path if "text/html" not in p["headers"].get("content-type", "") else None
        exposed = [p for _, p in pmap(probe, SENSITIVE_PROBES, 6) if p]
        res.data["exposed_paths"] = exposed
        for p in exposed:
            res.add("high", f"Sensitive path accessible: {p}", f"{base_url}{p}")
    return res
