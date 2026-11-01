"""Historical URLs from the Internet Archive: forgotten endpoints and leaked files."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import Context, Result, http_json

NAME = "wayback"
DESC = "Archived URLs: sensitive files, admin paths, parameters and historical subdomains"
PHASE = 1

SENSITIVE_EXT = re.compile(r"\.(env|sql|bak|backup|old|zip|tar|gz|7z|rar|log|pem|key|pfx|p12|git|svn|ini|conf|cfg|"
                           r"yml|yaml|xlsx?|csv|docx?|db|sqlite|dump|swp)(\?|$)", re.I)
SENSITIVE_PATH = re.compile(r"(/admin|/wp-admin|/phpmyadmin|/backup|/\.git|/\.env|/config|/internal|/private|"
                            r"/debug|/console|/swagger|/api-docs|/graphql|/actuator|/jenkins|/manager/html)", re.I)


def run(ctx: Context) -> Result:
    res = Result(NAME)
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{ctx.target}&output=json&fl=original,statuscode,timestamp"
           f"&collapse=urlkey&limit=8000&filter=statuscode:200")
    rows = http_json(url, timeout=max(ctx.timeout, 40), retries=1)
    if not rows or len(rows) < 2:
        res.error = "No archive data returned"
        return res
    rows = rows[1:]
    urls = {r[0] for r in rows}
    hosts, params, sens, paths = {}, {}, [], []
    for u in urls:
        p = urlparse(u)
        h = (p.hostname or "").lower()
        if h:
            hosts[h] = hosts.get(h, 0) + 1
        for k in re.findall(r"[?&]([a-zA-Z0-9_\-]+)=", u):
            params[k] = params.get(k, 0) + 1
        if SENSITIVE_EXT.search(u):
            sens.append(u)
        elif SENSITIVE_PATH.search(p.path or ""):
            paths.append(u)

    res.data["archived_urls"] = len(urls)
    res.data["hosts"] = dict(sorted(hosts.items(), key=lambda x: -x[1])[:100])
    res.data["top_parameters"] = dict(sorted(params.items(), key=lambda x: -x[1])[:40])
    res.data["sensitive_files"] = sorted(sens)[:150]
    res.data["interesting_paths"] = sorted(paths)[:150]
    ctx.shared["wayback_hosts"] = list(hosts)
    if sens:
        res.add("medium", f"{len(sens)} archived URLs point to potentially sensitive file types",
                "Check whether these files are still reachable and rotate any secrets they contained", sorted(sens)[:15])
    if paths:
        res.add("low", f"{len(paths)} archived admin/debug-style paths", "Verify they are not exposed today", sorted(paths)[:15])
    return res
