"""DNS records for the apex domain."""
from __future__ import annotations

from ..core import Context, Result, pmap
from ..dnsutil import dns_alive, query, resolve_ips

NAME = "dns"
DESC = "A/AAAA/MX/NS/TXT/SOA/CAA records and hosting/mail provider hints"
PHASE = 1

MAIL_PROVIDERS = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast", "zoho.com": "Zoho Mail",
    "protonmail.ch": "Proton Mail", "mailgun.org": "Mailgun", "secureserver.net": "GoDaddy",
}
DNS_PROVIDERS = {
    "cloudflare.com": "Cloudflare", "awsdns": "AWS Route 53", "azure-dns": "Azure DNS",
    "googledomains.com": "Google Domains", "domaincontrol.com": "GoDaddy",
    "nsone.net": "NS1", "ultradns": "UltraDNS", "dnsmadeeasy.com": "DNS Made Easy",
}


def _provider(values: list[str], table: dict) -> list[str]:
    found = set()
    for v in values:
        for k, name in table.items():
            if k in v.lower():
                found.add(name)
    return sorted(found)


def run(ctx: Context) -> Result:
    res = Result(NAME)
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"]
    recs = dict(pmap(lambda t: (t, query(ctx.target, t, ctx.timeout)), types, 8))
    records = {t: v for t, v in (r for r in recs.values() if r)}
    if not records.get("A"):
        records["A"] = [ip for ip in resolve_ips(ctx.target) if ":" not in ip]
    if not any(records.values()) and not dns_alive():
        res.error = "DNS is unreachable from this machine; skipping to avoid false findings"
        return res
    res.data["records"] = {k: v for k, v in records.items() if v}
    ctx.shared["apex_ips"] = records.get("A", [])

    res.data["mail_providers"] = _provider(records.get("MX", []), MAIL_PROVIDERS)
    res.data["dns_providers"] = _provider(records.get("NS", []), DNS_PROVIDERS)

    # TXT-based service discovery (reveals SaaS the company uses)
    verifs = {
        "google-site-verification": "Google", "MS=": "Microsoft 365", "atlassian-domain-verification": "Atlassian",
        "facebook-domain-verification": "Meta", "docusign": "DocuSign", "stripe-verification": "Stripe",
        "zoom": "Zoom", "slack-domain-verification": "Slack", "apple-domain-verification": "Apple",
        "adobe-idp-site-verification": "Adobe", "hubspot": "HubSpot", "amazonses": "Amazon SES",
        "onetrust": "OneTrust", "cisco-ci-domain-verification": "Cisco",
    }
    saas = sorted({v for t in records.get("TXT", []) for k, v in verifs.items() if k.lower() in t.lower()})
    res.data["saas_footprint"] = saas

    if not records.get("A") and not records.get("AAAA"):
        res.add("info", "Apex domain does not resolve to an address", "No A/AAAA records found")
    if not records.get("MX"):
        res.add("info", "No MX records", "Domain does not receive email (or uses a null MX)")
    if not records.get("CAA"):
        res.add("low", "No CAA record", "Any certificate authority may issue certificates for this domain")
    if len(records.get("NS", [])) == 1:
        res.add("medium", "Single nameserver", "Add a second nameserver for resilience")
    return res
