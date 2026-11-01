"""Domain registration data via RDAP (no API key)."""
from __future__ import annotations

from datetime import datetime, timezone

from ..core import Context, Result, http_json

NAME = "whois"
DESC = "Registrar, creation/expiry dates, status and nameservers (RDAP)"
PHASE = 1


def _parse_date(s: str):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def run(ctx: Context) -> Result:
    res = Result(NAME)
    j = http_json(f"https://rdap.org/domain/{ctx.target}", timeout=ctx.timeout + 8)
    if not j:
        res.error = "RDAP lookup failed or domain not found"
        return res

    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar = None
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vc = ent.get("vcardArray", [None, []])[1]
            for item in vc:
                if item[0] == "fn":
                    registrar = item[3]
    res.data = {
        "domain": j.get("ldhName"),
        "registrar": registrar,
        "status": j.get("status", []),
        "nameservers": sorted(n.get("ldhName", "").lower() for n in j.get("nameservers", [])),
        "events": events,
        "dnssec": j.get("secureDNS", {}).get("delegationSigned"),
    }

    now = datetime.now(timezone.utc)
    exp = _parse_date(events.get("expiration", "") or "")
    if exp:
        days = (exp - now).days
        res.data["days_to_expiry"] = days
        if days < 0:
            res.add("critical", "Domain registration has expired", f"Expired {-days} days ago")
        elif days < 30:
            res.add("high", "Domain expires within 30 days", f"{days} days left; enable auto-renew")
        elif days < 90:
            res.add("low", "Domain expires within 90 days", f"{days} days left")
    created = _parse_date(events.get("registration", "") or "")
    if created:
        res.data["age_days"] = (now - created).days

    status = " ".join(res.data["status"]).lower()
    if "clienttransferprohibited" not in status.replace(" ", ""):
        res.add("medium", "Registrar transfer lock not set",
                "Enable clientTransferProhibited to reduce domain-hijack risk")
    if res.data["dnssec"] is False:
        res.add("low", "DNSSEC is not enabled", "Zone is not signed; susceptible to DNS spoofing")
    return res
