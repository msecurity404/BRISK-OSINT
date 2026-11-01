"""Public GitHub footprint of the organisation and domain references in public code."""
from __future__ import annotations

import time

from ..core import Context, Result, http_json

NAME = "github"
DESC = "Org repositories, activity and (with GITHUB_TOKEN) domain/secret references in public code"
PHASE = 1


def run(ctx: Context) -> Result:
    res = Result(NAME)
    token = ctx.keys.get("github")
    hdr = {"Accept": "application/vnd.github+json"}
    if token:
        hdr["Authorization"] = f"Bearer {token}"
    handle = ctx.github or ctx.label

    kind = None
    prof = http_json(f"https://api.github.com/orgs/{handle}", headers=hdr, timeout=ctx.timeout)
    if prof:
        kind = "orgs"
    else:
        prof = http_json(f"https://api.github.com/users/{handle}", headers=hdr, timeout=ctx.timeout)
        kind = "users" if prof else None
    if not prof:
        res.data["handle"] = handle
        res.data["found"] = False
        res.error = f"No GitHub org/user named '{handle}' (use --github to set the handle)"
        return res

    res.data["profile"] = {k: prof.get(k) for k in ("login", "name", "type", "blog", "email", "location",
                                                    "public_repos", "followers", "created_at", "is_verified")}
    repos = []
    for page in (1, 2, 3):
        batch = http_json(f"https://api.github.com/{kind}/{handle}/repos?per_page=100&page={page}&sort=pushed",
                          headers=hdr, timeout=ctx.timeout)
        if not batch:
            break
        repos += batch
        if len(batch) < 100:
            break
    res.data["repos"] = [{"name": r["name"], "stars": r["stargazers_count"], "forks": r["forks_count"],
                          "language": r["language"], "pushed_at": r["pushed_at"], "archived": r["archived"],
                          "fork": r["fork"], "description": (r["description"] or "")[:120]} for r in repos]
    res.data["repo_count"] = len(repos)
    if prof.get("blog") and ctx.target not in prof["blog"]:
        res.add("info", "GitHub profile website differs from target domain", prof["blog"])
    if prof.get("type") == "User" or kind == "users":
        res.add("low", "Handle is a personal user, not a verified organization",
                f"github.com/{handle} could be unrelated to the company; verify before trusting")
    if repos:
        res.add("info", f"{len(repos)} public repositories under '{handle}'",
                "Review for internal tooling, credentials, or infrastructure details")

    # code search needs auth
    if token:
        own = {r["full_name"].lower() for r in repos}
        hits = []
        for q in (f'"{ctx.target}"', f'"{ctx.target}" password', f'"{ctx.target}" api_key', f'"{ctx.target}" secret'):
            j = http_json(f"https://api.github.com/search/code?q={q.replace(' ', '+')}&per_page=30",
                          headers=hdr, timeout=ctx.timeout)
            for it in (j or {}).get("items", []):
                fn = it["repository"]["full_name"].lower()
                if fn not in own:
                    hits.append({"query": q, "repo": it["repository"]["full_name"], "path": it["path"],
                                 "url": it["html_url"]})
            time.sleep(2.2)  # stay under the secondary rate limit
        res.data["external_code_references"] = hits[:100]
        if hits:
            sev = "high" if any("password" in h["query"] or "secret" in h["query"] or "api_key" in h["query"] for h in hits) else "medium"
            res.add(sev, f"{len(hits)} public code files outside your org reference {ctx.target}",
                    "Review for leaked credentials or internal endpoints", hits[:10])
    else:
        res.data["note"] = "Set GITHUB_TOKEN to enable code-search for leaked references"
    return res
