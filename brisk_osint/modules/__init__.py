"""Module registry. Each module exposes NAME, DESC, PHASE and run(ctx) -> Result."""
from . import (brand_handles, breaches, dns_recon, email_security, github_org,
               infra, subdomains, typosquat, wayback, web_fingerprint, whois_rdap)

ALL = [whois_rdap, dns_recon, email_security, web_fingerprint, subdomains, typosquat,
       wayback, github_org, brand_handles, breaches, infra]

REGISTRY = {m.NAME: m for m in ALL}

PROFILES = {
    "quick": ["whois", "dns", "email", "web"],
    "standard": ["whois", "dns", "email", "web", "subdomains", "infra", "breaches"],
    "full": [m.NAME for m in ALL],
}
