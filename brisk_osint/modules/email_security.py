"""Email spoofing posture: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI."""
from __future__ import annotations

import re

from ..core import Context, Result, pmap
from ..dnsutil import dns_alive, query

NAME = "email"
DESC = "SPF / DMARC / DKIM / MTA-STS / BIMI analysis and spoofability grade"
PHASE = 1

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2",
                  "smtp", "mandrill", "mxvault", "zoho", "protonmail", "sendgrid", "mailgun", "everlytickey1",
                  "cm", "dkim1", "krs", "m1", "scph0220", "pm"]
LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def parse_spf(txt: str) -> dict:
    parts = txt.split()
    qual = None
    lookups = 0
    includes = []
    for p in parts[1:]:
        base = p.lstrip("+-~?")
        if base == "all":
            qual = p[0] if p[0] in "+-~?" else "+"
        low = base.lower()
        if low.startswith(("include:", "exists:", "redirect=")) or low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            lookups += 1
        if low.startswith("include:"):
            includes.append(base[8:])
    return {"record": txt, "all": qual, "lookups": lookups, "includes": includes}


def parse_dmarc(txt: str) -> dict:
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def run(ctx: Context) -> Result:
    res = Result(NAME)
    d = ctx.target
    score = 100

    # SPF
    txts = query(d, "TXT", ctx.timeout)
    if not txts and not dns_alive():
        res.error = "DNS is unreachable from this machine; skipping to avoid false findings"
        return res
    spf =[t for t in txts if t.lower().startswith("v=spf1")]
    mx = query(d, "MX", ctx.timeout)
    receives_mail = bool(mx) and not (len(mx) == 1 and mx[0].endswith(" ."))
    if not spf:
        res.data["spf"] = None
        res.add("high" if receives_mail else "medium", "No SPF record",
                "Anyone can send mail claiming to be this domain without SPF failing")
        score -= 30
    else:
        if len(spf) > 1:
            res.add("high", "Multiple SPF records", "RFC 7208 allows one; receivers return permerror")
            score -= 15
        p = parse_spf(spf[0])
        res.data["spf"] = p
        if p["all"] == "+" or p["all"] == "?":
            res.add("high", "SPF is permissive", f"Policy '{p['all']}all' authorises every sender")
            score -= 25
        elif p["all"] == "~":
            res.add("low", "SPF uses softfail (~all)", "Move to -all once all senders are enumerated")
            score -= 5
        elif p["all"] is None:
            res.add("medium", "SPF has no 'all' mechanism", "Add a terminating -all")
            score -= 10
        if p["lookups"] > 10:
            res.add("medium", "SPF exceeds 10 DNS lookups", f"{p['lookups']} lookups; validation will fail")
            score -= 8

    # DMARC
    dm = [t for t in query(f"_dmarc.{d}", "TXT", ctx.timeout) if t.lower().startswith("v=dmarc1")]
    if not dm:
        res.data["dmarc"] = None
        res.add("high", "No DMARC record", "Spoofed mail is not rejected or reported; phishing risk")
        score -= 30
    else:
        t = parse_dmarc(dm[0])
        res.data["dmarc"] = t
        pol = t.get("p", "none").lower()
        if pol == "none":
            res.add("medium", "DMARC policy is 'none' (monitor only)", "Move to quarantine then reject")
            score -= 15
        elif pol == "quarantine":
            res.add("low", "DMARC policy is 'quarantine'", "Consider p=reject for full spoofing protection")
            score -= 4
        if "rua" not in t:
            res.add("low", "DMARC has no aggregate reporting address (rua)", "You will not see abuse of your domain")
            score -= 3
        if t.get("pct") and t["pct"].isdigit() and int(t["pct"]) < 100:
            res.add("low", f"DMARC applies to only {t['pct']}% of mail")
        if "sp" not in t and pol != "reject":
            res.data.setdefault("notes", []).append("No subdomain policy (sp) set")

    # DKIM
    def dkim(sel):
        r = query(f"{sel}._domainkey.{d}", "TXT", ctx.timeout) or query(f"{sel}._domainkey.{d}", "CNAME", ctx.timeout)
        return r
    found = {sel: r[0][:120] for sel, r in pmap(dkim, DKIM_SELECTORS, 12) if r}
    res.data["dkim_selectors"] = found
    if not found and receives_mail:
        res.add("info", "No common DKIM selectors found", "Selectors are arbitrary; this may be a false negative")

    # MTA-STS / TLS-RPT / BIMI
    mta = [t for t in query(f"_mta-sts.{d}", "TXT", ctx.timeout) if "v=STSv1" in t]
    res.data["mta_sts"] = bool(mta)
    res.data["tls_rpt"] = bool(query(f"_smtp._tls.{d}", "TXT", ctx.timeout))
    res.data["bimi"] = bool(query(f"default._bimi.{d}", "TXT", ctx.timeout))
    if receives_mail and not mta:
        res.add("low", "MTA-STS not configured", "Inbound SMTP TLS can be downgraded by an on-path attacker")
        score -= 3

    res.data["spoofability_score"] = max(0, score)
    res.data["receives_mail"] = receives_mail
    return res
