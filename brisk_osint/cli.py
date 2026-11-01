"""Command-line interface and scan orchestration."""
from __future__ import annotations

import argparse
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from . import branding
from .branding import GOLD, GOLD_LIGHT, PURPLE_LIGHT, paint
from .core import SEV_ORDER, VERSION, Context, Result, risk_score
from .modules import PROFILES, REGISTRY
from .report import SEV_COLORS, sorted_findings, write_all

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_lock = threading.Lock()


def normalize_target(t: str) -> str:
    t = t.strip().lower()
    t = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]
    if t.startswith("www."):
        t = t[4:]
    try:
        t = t.encode("idna").decode()
    except UnicodeError:
        pass
    return t


def run_module(mod, ctx: Context) -> Result:
    start = time.time()
    try:
        res = mod.run(ctx)
    except Exception as e:  # noqa: BLE001 - one module must never kill the scan
        res = Result(mod.NAME)
        res.error = f"{type(e).__name__}: {e}"
    res.elapsed = round(time.time() - start, 1)
    return res


def scan(ctx: Context, names: list[str], color: bool, quiet: bool) -> dict:
    started = datetime.now()
    t0 = time.time()
    results: dict[str, Result] = {}

    def log(res: Result):
        if quiet:
            return
        ok = not res.error
        mark = paint("✔", "#7FD6A3", color, True) if ok else paint("✖", "#FF4D6D", color, True)
        n = len(res.findings)
        note = f" - {paint(res.error, '#FF8A8A', color)}" if res.error else ""
        with _lock:
            print(f"  {mark} {paint(res.module.ljust(11), PURPLE_LIGHT, color, True)}"
                  f"{str(n).rjust(3)} findings  {paint(str(res.elapsed) + 's', '#8F83AD', color)}{note}")

    for phase in (1, 2):
        mods = [REGISTRY[n] for n in names if REGISTRY[n].PHASE == phase]
        if not mods:
            continue
        with ThreadPoolExecutor(max_workers=len(mods)) as ex:
            futs = [ex.submit(run_module, m, ctx) for m in mods]
            for f in as_completed(futs):
                r = f.result()
                results[r.module] = r
                log(r)

    findings = [f for n in names if n in results for f in results[n].findings]
    score = risk_score(findings)
    counts = {k: sum(1 for f in findings if f.severity == k) for k in SEV_COLORS}
    return {
        "meta": {"target": ctx.target, "tool": "brisk-osint", "version": VERSION, "author": branding.AUTHOR,
                 "started": started.isoformat(timespec="seconds"), "finished": datetime.now().isoformat(timespec="seconds"),
                 "duration": round(time.time() - t0, 1), "modules": [n for n in names if n in results],
                 "options": {"passive": ctx.passive, "active": ctx.active}},
        "score": score,
        "counts": counts,
        "findings": sorted_findings([f.to_dict() for f in findings]),
        "modules": {n: {"data": results[n].data, "error": results[n].error, "elapsed": results[n].elapsed,
                        "findings": [f.to_dict() for f in results[n].findings]} for n in names if n in results},
    }


def print_summary(report: dict, color: bool, paths: list[str], top: int = 12) -> None:
    s = report["score"]
    gc = "#7FD6A3" if s["value"] >= 80 else "#FFC93C" if s["value"] >= 55 else "#FF4D6D"
    print(f"\n  {paint('Target', GOLD, color, True)} {report['meta']['target']}    "
          f"{paint('Score', GOLD, color, True)} {paint(str(s['value']) + '/100 (' + s['grade'] + ')', gc, color, True)}    "
          f"{report['meta']['duration']}s")
    print("  " + "  ".join(paint(f"{k.upper()} {v}", SEV_COLORS[k], color, True) for k, v in report["counts"].items()))
    failed = [n for n, m in report["modules"].items() if m["error"]]
    if failed and len(failed) >= max(1, len(report["modules"]) - 1):
        print("  " + paint("! Most modules failed - check your internet/DNS access; the score above is not meaningful.",
                           "#FF8A3D", color, True))
    shown = [f for f in report["findings"] if SEV_ORDER[f["severity"]] >= 2][:top]
    if shown:
        print(f"\n  {paint('Top findings', GOLD_LIGHT, color, True)}")
        for f in shown:
            print(f"   {paint(f['severity'][:4].upper().ljust(5), SEV_COLORS[f['severity']], color, True)}"
                  f"{f['title']}  {paint('[' + f['module'] + ']', '#8F83AD', color)}")
    print(f"\n  {paint('Reports', GOLD_LIGHT, color, True)}")
    for p in paths:
        print(f"   {p}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="brisk-osint", description="Brisk OSINT - external attack-surface & brand intelligence framework.",
                                epilog=f"Developed by {branding.AUTHOR}. Use only on assets you own or are authorised to assess.")
    p.add_argument("targets", nargs="*", help="domain(s) to investigate, e.g. brisk.com")
    p.add_argument("-p", "--profile", choices=list(PROFILES), default="full", help="module set (default: full)")
    p.add_argument("-m", "--modules", help="comma-separated modules (overrides profile)")
    p.add_argument("-x", "--exclude", help="comma-separated modules to skip")
    p.add_argument("--list-modules", action="store_true", help="list modules and exit")
    p.add_argument("-o", "--output", default="brisk-reports", help="output directory (default: ./brisk-reports)")
    p.add_argument("-f", "--format", default="json,html,md", help="report formats: json,html,md")
    p.add_argument("-t", "--threads", type=int, default=40, help="worker threads per module (default 40)")
    p.add_argument("--timeout", type=int, default=10, help="network timeout seconds (default 10)")
    p.add_argument("--passive", action="store_true", help="skip DNS brute-force")
    p.add_argument("--active", action="store_true", help="enable light exposure probes (.git/.env/...) against the target")
    p.add_argument("--wordlist", help="extra subdomain wordlist file")
    p.add_argument("--github", help="GitHub org/user handle (default: brand label)")
    p.add_argument("--brand", help="brand label for look-alike/handle checks (default: first label of the domain)")
    p.add_argument("--max-permutations", type=int, default=2500, help="cap on look-alike domains to test")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--version", action="version", version=f"brisk-osint {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    color = branding.use_color() and not args.no_color
    if not args.no_banner and not args.quiet:
        print(branding.banner(VERSION, color))

    if args.list_modules:
        for n, m in REGISTRY.items():
            print(f"  {paint(n.ljust(12), PURPLE_LIGHT, color, True)}{m.DESC}")
        return 0
    if not args.targets:
        print("error: no target given. Example: brisk-osint brisk.com", file=sys.stderr)
        return 2

    names = [n.strip() for n in args.modules.split(",")] if args.modules else list(PROFILES[args.profile])
    if args.exclude:
        skip = {n.strip() for n in args.exclude.split(",")}
        names = [n for n in names if n not in skip]
    bad = [n for n in names if n not in REGISTRY]
    if bad:
        print(f"error: unknown module(s): {', '.join(bad)}. See --list-modules", file=sys.stderr)
        return 2
    if "infra" in names:  # infra consumes dns + subdomains output
        for dep in ("dns", "subdomains"):
            if dep not in names:
                names.append(dep)
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    if any(f not in ("json", "html", "md", "markdown") for f in formats):
        print("error: --format accepts json, html, md", file=sys.stderr)
        return 2

    keys = {k: v for k, v in {"github": os.getenv("GITHUB_TOKEN"), "shodan": os.getenv("SHODAN_API_KEY")}.items() if v}
    rc = 0
    for raw in args.targets:
        target = normalize_target(raw)
        if not DOMAIN_RE.match(target):
            print(f"error: '{raw}' is not a valid domain", file=sys.stderr)
            rc = 2
            continue
        ctx = Context(target=target, timeout=args.timeout, threads=args.threads, passive=args.passive,
                      active=args.active, github=args.github, brand=args.brand, wordlist=args.wordlist,
                      max_permutations=args.max_permutations, keys=keys)
        if not args.quiet:
            print(f"  {paint('▶', GOLD, color, True)} Scanning {paint(target, GOLD_LIGHT, color, True)} "
                  f"with {len(names)} modules" + (" (active probes ON)" if args.active else "") + "\n")
        report = scan(ctx, names, color, args.quiet)
        outdir = os.path.join(args.output, f"{target}_{datetime.now():%Y%m%d-%H%M%S}")
        paths = write_all(report, outdir, formats)
        if not args.quiet:
            print_summary(report, color, paths)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
