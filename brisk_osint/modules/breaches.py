"""Public breach history for the domain (Have I Been Pwned breach catalogue)."""
from __future__ import annotations

from ..core import Context, Result, http_json

NAME = "breaches"
DESC = "Known public breaches of services on this domain (HIBP catalogue, no key needed)"
PHASE = 1


def run(ctx: Context) -> Result:
    res = Result(NAME)
    j = http_json(f"https://haveibeenpwned.com/api/v3/breaches?domain={ctx.target}", timeout=ctx.timeout + 5)
    if j is None:
        res.error = "HIBP lookup failed"
        return res
    rows = [{"name": b.get("Name"), "title": b.get("Title"), "breach_date": b.get("BreachDate"),
             "added": b.get("AddedDate", "")[:10], "pwn_count": b.get("PwnCount"),
             "data_classes": b.get("DataClasses", []), "verified": b.get("IsVerified")} for b in j]
    res.data["breaches"] = rows
    res.data["count"] = len(rows)
    for b in rows:
        sensitive = {"Passwords", "Password hints", "Credit cards", "Bank account numbers", "Government issued IDs"}
        sev = "high" if sensitive & set(b["data_classes"]) else "medium"
        res.add(sev, f"Public breach recorded: {b['title']}",
                f"{b['pwn_count']:,} accounts, {b['breach_date']}; data: {', '.join(b['data_classes'][:6])}", b)
    if not rows:
        res.add("info", "No breaches of this domain in the HIBP catalogue")
    return res
