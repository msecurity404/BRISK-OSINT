"""Brand protection: look-alike domain permutations, registration and phishing-page checks."""
from __future__ import annotations

import re

from ..core import Context, Result, http, pmap
from ..dnsutil import HAVE_DNSPYTHON, query, resolve_a

NAME = "typosquat"
DESC = "Generate look-alike domains, find registered ones, flag mail-capable & phishing pages"
PHASE = 1

QWERTY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "ol", "a": "qsz", "s": "awdx", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn",
    "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "s": ["5"], "a": ["4"],
              "m": ["rn"], "w": ["vv"], "d": ["cl"], "b": ["6"]}
UNICODE_GLYPHS = {"a": "а", "e": "е", "o": "о", "i": "і", "c": "с", "p": "р", "s": "ѕ", "x": "х", "y": "у"}
TLDS = ["com", "net", "org", "io", "co", "app", "dev", "biz", "info", "xyz", "online", "site", "shop", "top",
        "store", "tech", "cloud", "ai", "me", "cc", "club", "live", "pro", "ps", "il", "ae", "sa", "eu", "us"]
KEYWORDS = ["login", "secure", "support", "app", "online", "official", "portal", "account", "my", "verify",
            "pay", "mail", "web", "help", "service", "get", "go"]
SLD2 = {"co.uk", "com.au", "co.il", "org.il", "com.ps", "com.br", "co.za", "com.tr", "com.sa", "com.eg", "co.in"}
VOWELS = "aeiou"


def split_domain(d: str) -> tuple[str, str]:
    parts = d.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SLD2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def permutations(domain: str, limit: int = 2500) -> dict[str, str]:
    name, tld = split_domain(domain)
    out: dict[str, str] = {}

    def add(n: str, t: str, kind: str):
        n = n.strip("-.")
        if not n or n == name and t == tld:
            return
        if len(n) > 63 or ".." in n:
            return
        try:
            cand = f"{n}.{t}".encode("idna").decode()
        except UnicodeError:
            return
        if cand != domain:
            out.setdefault(cand, kind)

    for t in TLDS:
        add(name, t, "tld-swap")
    for k in KEYWORDS:
        for n in (f"{name}-{k}", f"{k}-{name}", f"{name}{k}", f"{k}{name}"):
            add(n, tld, "keyword")
            add(n, "com", "keyword")
    for i, ch in enumerate(name):
        if ch in UNICODE_GLYPHS:
            add(name[:i] + UNICODE_GLYPHS[ch] + name[i + 1:], tld, "homoglyph-unicode")
        for g in HOMOGLYPHS.get(ch, []):
            add(name[:i] + g + name[i + 1:], tld, "homoglyph")
    for i in range(len(name) - 1):
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:], tld, "transposition")
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], tld, "omission")
        add(name[:i] + name[i] * 2 + name[i:], tld, "repetition")
        for r in QWERTY.get(name[i], ""):
            add(name[:i] + r + name[i + 1:], tld, "replacement")
            add(name[:i] + r + name[i:], tld, "insertion")
        add(name[:i] + "-" + name[i:], tld, "hyphenation")
        if name[i] in VOWELS:
            for v in VOWELS:
                add(name[:i] + v + name[i + 1:], tld, "vowel-swap")
        for bit in range(8):
            c = chr(ord(name[i]) ^ (1 << bit))
            if re.fullmatch(r"[a-z0-9-]", c):
                add(name[:i] + c + name[i + 1:], tld, "bitsquat")
    return dict(list(out.items())[:limit])


def run(ctx: Context) -> Result:
    res = Result(NAME)
    perms = permutations(ctx.target, ctx.max_permutations)
    res.data["generated"] = len(perms)

    def check(dom):
        a = resolve_a(dom)
        ns = query(dom, "NS", 3) if (not a and HAVE_DNSPYTHON) else []
        if not a and not ns:
            return None
        mx = query(dom, "MX", 3) if HAVE_DNSPYTHON or a else []
        return {"kind": perms[dom], "ips": a, "ns": ns[:3], "mx": mx[:3]}

    reg = {d: v for d, v in pmap(check, list(perms), ctx.threads) if v}
    res.data["registered_count"] = len(reg)

    # inspect web content on a bounded set
    brand = ctx.label
    web_hits = []

    def inspect(dom):
        for scheme in ("https", "http"):
            r = http(f"{scheme}://{dom}/", timeout=6, retries=0, max_bytes=250_000)
            if r["status"]:
                t = r["text"].lower()
                m = re.search(r"<title[^>]*>(.*?)</title>", r["text"], re.I | re.S)
                return {"status": r["status"], "title": (m.group(1).strip()[:100] if m else None),
                        "mentions_brand": brand in t, "login_form": 'type="password"' in t or "type='password'" in t,
                        "final_url": r["url"]}
        return None

    targets = [d for d, v in reg.items() if v["ips"]][:60]
    for dom, info in pmap(inspect, targets, 20):
        if info:
            reg[dom]["web"] = info
            if info["login_form"] and info["mentions_brand"]:
                res.add("critical", f"Possible phishing page: {dom}",
                        f"Look-alike ({reg[dom]['kind']}) with login form referencing '{brand}'", {dom: info})
                web_hits.append(dom)
            elif info["mentions_brand"]:
                res.add("high", f"Look-alike site mentions your brand: {dom}", f"Title: {info['title']}", {dom: info})
                web_hits.append(dom)

    mail_capable = [d for d, v in reg.items() if v["mx"] and d not in web_hits]
    if mail_capable:
        res.add("medium", f"{len(mail_capable)} look-alike domains can send/receive email",
                ", ".join(sorted(mail_capable)[:10]), sorted(mail_capable))
    other = len(reg) - len(web_hits) - len(mail_capable)
    if other > 0:
        res.add("low", f"{other} other registered look-alike domains", "Monitor for changes / consider defensive registration")
    res.data["registered"] = dict(sorted(reg.items()))
    return res
