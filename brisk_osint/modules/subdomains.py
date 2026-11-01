"""Subdomain discovery: certificate transparency + passive DNS + light DNS brute-force."""
from __future__ import annotations

import re

from ..core import Context, Result, http, http_json, pmap, rand_label
from ..dnsutil import query, resolve_a

NAME = "subdomains"
DESC = "crt.sh, AlienVault OTX, HackerTarget, DNS brute-force, takeover & exposure checks"
PHASE = 1

COMMON = """www mail remote blog webmail server ns1 ns2 smtp secure vpn m shop ftp mail2 test portal ns dev admin api
staging stage beta demo app apps cdn static assets img images media support help docs status git gitlab github jenkins ci
cd grafana kibana prometheus elastic monitor monitoring intranet internal corp office sso auth login id accounts account
oauth idp crm erp hr billing pay payments checkout store old new v1 v2 uat qa preprod prod sandbox backup db sql mysql
postgres redis mongo rabbit mq kafka s3 files file download uploads upload mx mx1 mx2 imap pop pop3 autodiscover
autoconfig owa exchange sip meet chat wiki confluence jira bitbucket sonar nexus artifactory registry docker k8s kube
cluster traefik proxy gateway gw edge lb fw router wifi guest mobile web web1 web2 app1 app2 api2 graphql ws socket stream
live video news events careers jobs partners partner dashboard panel cpanel whm webdisk ns3 ns4 dns dns1 dns2 ntp ldap ad
dc radius vpn2 ssl cert pki ca bot bots ai ml data analytics metrics logs log splunk elk sentry tracker track""".split()

INTERESTING = re.compile(r"^(dev|test|stag|stage|uat|qa|admin|jenkins|grafana|kibana|vpn|git|gitlab|jira|confluence|"
                         r"phpmyadmin|backup|old|internal|intranet|sso|beta|sandbox|preprod|prometheus|sonar|nexus|"
                         r"artifactory|registry|splunk|elk|rabbit|redis|mongo|sql|db)\b", re.I)

# CNAME suffix -> (service, body fingerprint of an unclaimed resource or None)
TAKEOVER = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "herokudns.com": ("Heroku", "No such app"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "amazonaws.com": ("AWS", "NoSuchBucket"),
    "azurewebsites.net": ("Azure App Service", None),
    "cloudapp.net": ("Azure Cloud Service", None),
    "trafficmanager.net": ("Azure Traffic Manager", None),
    "blob.core.windows.net": ("Azure Blob", "NoSuchBucket"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "surge.sh": ("Surge", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "netlify.app": ("Netlify", "Not Found - Request ID"),
    "readme.io": ("Readme", "Project doesnt exist"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "unbouncepages.com": ("Unbounce", "The requested URL was not found"),
}


def _valid(host: str, domain: str) -> bool:
    host = host.lower().strip().lstrip("*.")
    return bool(re.fullmatch(r"[a-z0-9._-]+", host)) and (host == domain or host.endswith("." + domain))


def from_crtsh(domain: str, timeout: int) -> set[str]:
    j = http_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=max(timeout, 30), retries=1)
    out = set()
    for row in j or []:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if _valid(n, domain):
                out.add(n)
    return out


def from_otx(domain: str, timeout: int) -> set[str]:
    j = http_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=timeout)
    return {r["hostname"].lower() for r in (j or {}).get("passive_dns", []) if _valid(r.get("hostname", ""), domain)}


def from_hackertarget(domain: str, timeout: int) -> set[str]:
    r = http(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout, retries=0)
    out = set()
    if r["status"] == 200 and "error" not in r["text"][:20].lower():
        for line in r["text"].splitlines():
            h = line.split(",")[0].strip().lower()
            if _valid(h, domain):
                out.add(h)
    return out


def run(ctx: Context) -> Result:
    res = Result(NAME)
    d = ctx.target
    sources: dict[str, set[str]] = {}
    for name, fn in (("crt.sh", from_crtsh), ("otx", from_otx), ("hackertarget", from_hackertarget)):
        try:
            sources[name] = fn(d, ctx.timeout)
        except Exception:  # noqa: BLE001
            sources[name] = set()
    res.data["sources"] = {k: len(v) for k, v in sources.items()}
    found = set().union(*sources.values())

    # wildcard detection + brute force
    wild = set(resolve_a(f"{rand_label()}.{d}"))
    res.data["wildcard_dns"] = sorted(wild)
    if not ctx.passive:
        words = set(COMMON)
        if ctx.wordlist:
            try:
                with open(ctx.wordlist, encoding="utf-8", errors="ignore") as fh:
                    words |= {w.strip().lower() for w in fh if w.strip() and not w.startswith("#")}
            except OSError as e:
                res.error = f"wordlist: {e}"
        cand = [f"{w}.{d}" for w in words if f"{w}.{d}" not in found]
        brute_hits = {h for h, ips in pmap(lambda h: resolve_a(h), cand, ctx.threads) if ips and not set(ips) <= wild}
        res.data["sources"]["bruteforce"] = len(brute_hits)
        found |= brute_hits

    found.add(d)
    hosts = sorted(found)[:2500]

    def resolve(host):
        ips = resolve_a(host)
        cname = query(host, "CNAME", 4) if host != d else []
        return {"ips": ips, "cname": cname[0] if cname else None}

    live: dict[str, dict] = {}
    dead: list[str] = []
    for host, info in pmap(resolve, hosts, ctx.threads):
        if info and (info["ips"] or info["cname"]):
            live[host] = info
        else:
            dead.append(host)
    res.data["total_found"] = len(hosts)
    res.data["resolving"] = {h: live[h] for h in sorted(live)}
    res.data["non_resolving"] = sorted(dead)[:300]
    ctx.shared["subdomains"] = {h: v["ips"] for h, v in live.items()}

    # interesting exposure by name
    hot = sorted(h for h in live if INTERESTING.match(h[: -len(d) - 1]) and h != d)
    res.data["interesting_hosts"] = hot
    if hot:
        res.add("medium", f"{len(hot)} internal/dev-looking hosts are publicly resolvable",
                ", ".join(hot[:12]), hot)

    # takeover candidates
    def check_takeover(host):
        info = live[host]
        cn = (info["cname"] or "").lower()
        for suffix, (service, sig) in TAKEOVER.items():
            if cn.endswith(suffix):
                if not info["ips"]:
                    return (host, cn, service, "dangling")
                if sig:
                    for scheme in ("https", "http"):
                        r = http(f"{scheme}://{host}/", timeout=ctx.timeout, retries=0, max_bytes=60_000)
                        if r["status"] and sig.lower() in r["text"].lower():
                            return (host, cn, service, "fingerprint")
        return None

    cands = [h for h in live if live[h]["cname"]]
    tk = [t for _, t in pmap(check_takeover, cands, 12) if t]
    res.data["takeover_candidates"] = [{"host": h, "cname": c, "service": s, "evidence": e} for h, c, s, e in tk]
    for h, c, s, e in tk:
        if e == "fingerprint":
            res.add("critical", f"Subdomain takeover likely: {h}", f"CNAME -> {c} ({s}) shows unclaimed-resource page")
        else:
            res.add("high", f"Dangling CNAME: {h}", f"Points to {c} ({s}) which does not resolve; may be claimable")

    res.data["count_live"] = len(live)
    if len(live) > 50:
        res.add("info", f"Large external footprint: {len(live)} live hostnames",
                "Review for forgotten or unmaintained assets")
    return res
