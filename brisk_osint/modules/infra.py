"""Infrastructure intelligence: IP ownership + open ports/CVE hints (Shodan InternetDB, free)."""
from __future__ import annotations

from ..core import Context, Result, http_json, pmap

NAME = "infra"
DESC = "IP ownership (RDAP), exposed ports & known CVEs via Shodan InternetDB (optional Shodan key)"
PHASE = 2  # needs dns + subdomains results

RISKY = {21: "FTP", 23: "Telnet", 135: "MSRPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
         2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
         6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 5601: "Kibana", 9090: "Prometheus"}


def run(ctx: Context) -> Result:
    res = Result(NAME)
    host_ips: dict[str, list[str]] = {}
    for ip in ctx.shared.get("apex_ips", []):
        host_ips.setdefault(ip, []).append(ctx.target)
    for host, ips in ctx.shared.get("subdomains", {}).items():
        for ip in ips:
            host_ips.setdefault(ip, []).append(host)
    ips = sorted(host_ips)[:80]
    if not ips:
        res.error = "No IP addresses collected from dns/subdomains modules"
        return res

    skey = ctx.keys.get("shodan")

    def lookup(ip):
        info = http_json(f"https://internetdb.shodan.io/{ip}", timeout=ctx.timeout, retries=0) or {}
        if skey:
            full = http_json(f"https://api.shodan.io/shodan/host/{ip}?key={skey}", timeout=ctx.timeout + 5, retries=0)
            if full:
                info["org"] = full.get("org")
                info["isp"] = full.get("isp")
                info["banners"] = [{"port": d.get("port"), "product": d.get("product"), "version": d.get("version")}
                                   for d in full.get("data", [])][:20]
        return info

    rows = {}
    for ip, info in pmap(lookup, ips, 8):
        if info is not None:
            rows[ip] = {"hosts": sorted(set(host_ips[ip]))[:10], **info}

    def own(ip):
        j = http_json(f"https://rdap.org/ip/{ip}", timeout=ctx.timeout + 4, retries=0)
        if not j:
            return None
        return {"name": j.get("name"), "country": j.get("country"), "handle": j.get("handle"),
                "range": f"{j.get('startAddress')} - {j.get('endAddress')}"}

    for ip, o in pmap(own, ips[:25], 8):
        if o and ip in rows:
            rows[ip]["network"] = o

    res.data["ips"] = rows
    res.data["unique_ips"] = len(ips)
    networks = sorted({r["network"]["name"] for r in rows.values() if r.get("network", {}).get("name")})
    res.data["networks"] = networks

    for ip, r in rows.items():
        ports = r.get("ports", [])
        risky = [(p, RISKY[p]) for p in ports if p in RISKY]
        if risky:
            sev = "high" if any(p in (23, 445, 2375, 3389, 5900, 6379, 9200, 11211, 27017, 3306, 5432, 1433) for p, _ in risky) else "medium"
            res.add(sev, f"Risky service(s) exposed on {ip}",
                    ", ".join(f"{p}/{n}" for p, n in risky) + f" (hosts: {', '.join(r['hosts'][:3])})", r)
        if r.get("vulns"):
            res.add("high" if len(r["vulns"]) > 3 else "medium", f"{len(r['vulns'])} potential CVEs associated with {ip}",
                    ", ".join(r["vulns"][:8]) + " (InternetDB is passive; verify before acting)", r["vulns"])
    all_ports = sorted({p for r in rows.values() for p in r.get("ports", [])})
    res.data["all_open_ports"] = all_ports
    return res
