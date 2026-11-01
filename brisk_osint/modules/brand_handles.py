"""Where does the organisation's brand handle exist (or not) across developer/social platforms."""
from __future__ import annotations

from ..core import Context, Result, http, pmap

NAME = "brands"
DESC = "Brand-handle presence on public platforms (find impersonation & unclaimed handles)"
PHASE = 1

# (platform, profile URL template, probe URL template or None, missing-marker in body)
PLATFORMS = [
    ("GitHub", "https://github.com/{h}", "https://api.github.com/users/{h}", None),
    ("GitLab", "https://gitlab.com/{h}", "https://gitlab.com/api/v4/users?username={h}", "[]"),
    ("npm", "https://www.npmjs.com/org/{h}", None, None),
    ("PyPI", "https://pypi.org/user/{h}/", None, None),
    ("Docker Hub", "https://hub.docker.com/u/{h}", "https://hub.docker.com/v2/users/{h}/", None),
    ("Reddit", "https://www.reddit.com/user/{h}", "https://www.reddit.com/user/{h}/about.json", None),
    ("YouTube", "https://www.youtube.com/@{h}", None, None),
    ("Medium", "https://medium.com/@{h}", None, None),
    ("dev.to", "https://dev.to/{h}", None, None),
    ("Telegram", "https://t.me/{h}", None, "tgme_page_extra"),
    ("Keybase", "https://keybase.io/{h}", None, None),
    ("Linktree", "https://linktr.ee/{h}", None, None),
]


def run(ctx: Context) -> Result:
    res = Result(NAME)
    h = ctx.label

    def probe(p):
        name, profile, api, marker = p
        r = http((api or profile).format(h=h), timeout=ctx.timeout, retries=0, max_bytes=120_000,
                 headers={"Accept-Language": "en"})
        if r["status"] is None:
            return {"platform": name, "status": "unknown"}
        if marker == "[]":
            exists = r["status"] == 200 and r["text"].strip() not in ("[]", "")
        elif marker:
            exists = r["status"] == 200 and marker in r["text"]
        else:
            exists = r["status"] == 200
        url = profile.format(h=h)
        if exists:
            return {"platform": name, "url": url, "status": "claimed"}
        if r["status"] in (404, 410) or (marker and r["status"] == 200):
            return {"platform": name, "url": url, "status": "available"}
        return {"platform": name, "url": url, "status": "unknown"}  # blocked / rate-limited / ambiguous

    rows = [r for _, r in pmap(probe, PLATFORMS, 10) if r]
    rows.sort(key=lambda r: r["platform"])
    res.data["handle"] = h
    res.data["platforms"] = rows
    claimed = [r for r in rows if r["status"] == "claimed"]
    free = [r["platform"] for r in rows if r["status"] == "available"]
    if claimed:
        res.add("info", f"Handle '{h}' exists on {len(claimed)} platforms",
                "Confirm each is official: " + ", ".join(r["url"] for r in claimed), claimed)
    if free:
        res.add("low", f"Handle '{h}' is unclaimed on {len(free)} platforms",
                "Register defensively to prevent impersonation: " + ", ".join(free), free)
    return res
