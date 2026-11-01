"""Report writers: JSON, Markdown and a self-contained branded HTML dashboard."""
from __future__ import annotations

import html
import json
import os
from datetime import datetime

from .branding import AUTHOR, logo_svg
from .core import SEV_ORDER, VERSION

SEV_COLORS = {"critical": "#FF4D6D", "high": "#FF8A3D", "medium": "#FFC93C", "low": "#7FD6A3", "info": "#8FA8FF"}


def sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-SEV_ORDER[f["severity"]], f["module"], f["title"]))


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)


def write_markdown(report: dict, path: str) -> None:
    m, s = report["meta"], report["score"]
    lines = [f"# Brisk OSINT report: {m['target']}", "",
             f"- Generated: {m['finished']}", f"- Score: **{s['value']}/100 (grade {s['grade']})**",
             f"- Modules: {', '.join(m['modules'])}", ""]
    counts = report["counts"]
    lines.append("| " + " | ".join(counts) + " |")
    lines.append("|" + "---|" * len(counts))
    lines.append("| " + " | ".join(str(v) for v in counts.values()) + " |")
    lines += ["", "## Findings", ""]
    for f in report["findings"]:
        lines.append(f"- **[{f['severity'].upper()}]** `{f['module']}` {f['title']}" + (f"  \n  {f['detail']}" if f["detail"] else ""))
    lines += ["", "## Module status", ""]
    for name, mod in report["modules"].items():
        lines.append(f"- `{name}`: {len(mod['findings'])} findings, {mod['elapsed']}s" + (f", error: {mod['error']}" if mod["error"] else ""))
    lines += ["", f"_Brisk OSINT v{VERSION} - Developed by {AUTHOR}_", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------- HTML ---

def _esc(v) -> str:
    return html.escape(str(v), quote=True)


def _render(v, depth=0, limit=300) -> str:
    if v is None or v == "" or v == [] or v == {}:
        return '<span class="muted">-</span>'
    if isinstance(v, bool):
        return '<span class="chip ' + ("ok" if v else "no") + '">' + str(v).lower() + "</span>"
    if isinstance(v, (str, int, float)):
        s = str(v)
        if s.startswith(("http://", "https://")):
            return f'<a href="{_esc(s)}" target="_blank" rel="noopener noreferrer">{_esc(s)}</a>'
        return _esc(s)
    if isinstance(v, list):
        if all(isinstance(x, (str, int, float)) for x in v):
            more = f'<span class="muted"> +{len(v) - limit} more</span>' if len(v) > limit else ""
            return "".join(f'<span class="chip">{_esc(x)}</span>' for x in v[:limit]) + more
        if all(isinstance(x, dict) for x in v):
            keys = list(dict.fromkeys(k for x in v[:limit] for k in x))
            head = "".join(f"<th>{_esc(k)}</th>" for k in keys)
            body = "".join("<tr>" + "".join(f"<td>{_render(x.get(k), depth + 1)}</td>" for k in keys) + "</tr>" for x in v[:limit])
            return f'<div class="tw"><table><tr>{head}</tr>{body}</table></div>'
        return "<br>".join(_render(x, depth + 1) for x in v[:limit])
    if isinstance(v, dict):
        rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_render(x, depth + 1)}</td></tr>" for k, x in list(v.items())[:limit])
        return f'<div class="tw"><table class="kv">{rows}</table></div>'
    return _esc(v)


CSS = """
:root{--bg:#0d0820;--bg2:#150a30;--card:#1a1038;--line:#2c1d57;--tx:#ece7fa;--mut:#9b90bd;--pu:#9b6be8;--pud:#5b2a9e;--go:#e5a91b;--gol:#ffd76a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#2a1360 0,var(--bg) 60%);color:var(--tx);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--gol)}.wrap{max-width:1100px;margin:0 auto;padding:20px 16px 60px}
.logo{max-width:560px;margin:8px auto 22px}.logo svg{width:100%;height:auto;display:block;filter:drop-shadow(0 10px 40px #5b2a9e66)}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:20px}
.top{display:grid;grid-template-columns:220px 1fr;gap:16px;margin-bottom:18px}@media(max-width:720px){.top{grid-template-columns:1fr}}
.card{background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:16px;padding:16px}
.gauge{display:grid;place-items:center}.ring{--p:0;width:150px;height:150px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient(var(--c) calc(var(--p)*1%),#2a1d52 0)}.ring>div{width:118px;height:118px;border-radius:50%;background:var(--bg2);display:grid;place-items:center;text-align:center}
.ring b{font-size:34px;line-height:1}.ring small{color:var(--mut)}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.cnt{border-radius:12px;padding:12px;text-align:center;background:#ffffff08;border:1px solid var(--line)}
.cnt b{display:block;font-size:26px}.cnt span{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}.bar button,.bar input{background:var(--card);color:var(--tx);border:1px solid var(--line);border-radius:999px;padding:7px 14px;font:inherit;cursor:pointer}
.bar button.on{background:linear-gradient(90deg,var(--pud),var(--go));border-color:transparent;color:#fff}.bar input{flex:1;min-width:180px;cursor:text}
.f{border-left:4px solid var(--c);margin:8px 0;padding:10px 14px;background:#ffffff06;border-radius:0 12px 12px 0}.f b{font-size:15px}
.sev{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#111;background:var(--c);border-radius:6px;padding:1px 7px;margin-right:8px}
.mod{font-size:12px;color:var(--mut);margin-left:6px}.d{color:var(--mut);font-size:14px;margin-top:3px;word-break:break-word}
h2{margin:30px 0 10px;font-size:18px;color:var(--gol)}details{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:10px 0;overflow:hidden}
summary{cursor:pointer;padding:12px 16px;font-weight:600;list-style:none}summary::-webkit-details-marker{display:none}summary:before{content:"\\25B8";color:var(--go);margin-right:8px}
details[open] summary:before{content:"\\25BE"}summary .muted{font-weight:400}.pad{padding:4px 16px 16px}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{color:var(--mut);font-weight:600;white-space:nowrap}.kv th{width:190px}.chip{display:inline-block;background:#9b6be822;border:1px solid #9b6be855;border-radius:7px;padding:1px 8px;margin:2px 4px 2px 0;font-size:12.5px}
.chip.ok{background:#7fd6a322;border-color:#7fd6a366}.chip.no{background:#ff4d6d22;border-color:#ff4d6d66}.muted{color:var(--mut)}
.err{color:#ff8a8a;margin:8px 0}footer{margin-top:40px;text-align:center;color:var(--mut);font-size:13px}footer b{color:var(--gol)}
"""

JS = """
const btns=[...document.querySelectorAll('.bar button')],q=document.getElementById('q');let sev='all';
function apply(){const t=q.value.toLowerCase();document.querySelectorAll('.f').forEach(f=>{
const ok=(sev==='all'||f.dataset.s===sev)&&f.textContent.toLowerCase().includes(t);f.style.display=ok?'':'none'})}
btns.forEach(b=>b.onclick=()=>{btns.forEach(x=>x.classList.remove('on'));b.classList.add('on');sev=b.dataset.s;apply()});q.oninput=apply;
"""


def write_html(report: dict, path: str) -> None:
    m, s = report["meta"], report["score"]
    ring_color = "#7FD6A3" if s["value"] >= 80 else "#FFC93C" if s["value"] >= 55 else "#FF4D6D"
    counts = "".join(f'<div class="cnt" style="border-color:{SEV_COLORS[k]}55"><b style="color:{SEV_COLORS[k]}">{v}</b><span>{k}</span></div>'
                     for k, v in report["counts"].items())
    filt = '<button class="on" data-s="all">All</button>' + "".join(
        f'<button data-s="{k}">{k.title()}</button>' for k in SEV_COLORS)
    finds = "".join(
        f'<div class="f" data-s="{f["severity"]}" style="--c:{SEV_COLORS[f["severity"]]}"><span class="sev">{f["severity"]}</span>'
        f'<b>{_esc(f["title"])}</b><span class="mod">{_esc(f["module"])}</span>'
        + (f'<div class="d">{_esc(f["detail"])}</div>' if f["detail"] else "") + "</div>"
        for f in report["findings"]) or '<div class="card muted">No findings.</div>'
    mods = ""
    for name, mod in report["modules"].items():
        err = f'<div class="err">{_esc(mod["error"])}</div>' if mod["error"] else ""
        mods += (f'<details><summary>{_esc(name)} <span class="muted">- {len(mod["findings"])} findings, {mod["elapsed"]}s</span></summary>'
                 f'<div class="pad">{err}{_render(mod["data"])}</div></details>')
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Brisk OSINT - {_esc(m['target'])}</title><style>{CSS}</style></head><body><div class="wrap">
<div class="logo">{logo_svg()}</div>
<h1>Target: {_esc(m['target'])}</h1><div class="sub">{_esc(m['finished'])} - {len(m['modules'])} modules - {m['duration']}s</div>
<div class="top"><div class="card gauge"><div class="ring" style="--p:{s['value']};--c:{ring_color}"><div><div><b>{s['value']}</b><br><small>Grade {s['grade']}</small></div></div></div></div>
<div class="card"><div class="counts">{counts}</div></div></div>
<h2>Findings</h2><div class="bar">{filt}<input id="q" placeholder="Search findings..."></div>{finds}
<h2>Module data</h2>{mods}
<footer>Brisk OSINT v{VERSION} - Developed by <b>{AUTHOR}</b><br>For authorized security assessment and brand protection only.</footer>
</div><script>{JS}</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def write_all(report: dict, outdir: str, formats: list[str]) -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    written = []
    for fmt in formats:
        p = os.path.join(outdir, f"report.{ {'markdown': 'md'}.get(fmt, fmt) }")
        {"json": write_json, "html": write_html, "md": write_markdown, "markdown": write_markdown}[fmt](report, p)
        written.append(p)
    return written
