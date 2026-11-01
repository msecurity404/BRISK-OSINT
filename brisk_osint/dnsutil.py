"""DNS helpers: dnspython when installed, DNS-over-HTTPS fallback otherwise."""
from __future__ import annotations

import re
import socket
import urllib.parse

from .core import http_json

try:  # optional dependency
    import dns.resolver  # type: ignore

    HAVE_DNSPYTHON = True
except Exception:  # noqa: BLE001
    HAVE_DNSPYTHON = False

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


def _clean_txt(s: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', s)
    return "".join(parts) if parts else s.strip('"')


def query(name: str, rtype: str = "A", timeout: int = 5) -> list[str]:
    name = name.rstrip(".")
    if HAVE_DNSPYTHON:
        try:
            res = dns.resolver.Resolver()
            res.lifetime = res.timeout = timeout
            ans = res.resolve(name, rtype)
        except Exception:  # noqa: BLE001
            return []
        out: list[str] = []
        for r in ans:
            if rtype == "MX":
                out.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
            elif rtype == "TXT":
                out.append("".join(s.decode("utf-8", "replace") for s in r.strings))
            elif rtype in ("CNAME", "NS", "PTR"):
                out.append(r.target.to_text().rstrip("."))
            else:
                out.append(r.to_text())
        return out
    # DNS-over-HTTPS fallback
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    j = http_json(url, headers={"Accept": "application/dns-json"}, timeout=timeout, retries=0)
    if not j:
        return []
    want = RTYPES.get(rtype)
    out = []
    for a in j.get("Answer", []) or []:
        if a.get("type") != want:
            continue
        d = a.get("data", "")
        out.append(_clean_txt(d) if rtype == "TXT" else d.rstrip("."))
    return out


_alive: bool | None = None


def dns_alive() -> bool:
    """True when DNS works at all (guards against reporting 'missing record' on a dead network)."""
    global _alive
    if _alive is None:
        _alive = bool(query("cloudflare.com", "A", 5)) or bool(resolve_ips("cloudflare.com"))
    return _alive


def resolve_ips(host: str) -> list[str]:
    """Fast A/AAAA lookup through the system resolver."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001
        return []
    return sorted({i[4][0] for i in infos})


def resolve_a(host: str) -> list[str]:
    return [ip for ip in resolve_ips(host) if ":" not in ip]
