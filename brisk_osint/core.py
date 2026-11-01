"""Core primitives: results, context, HTTP helper, thread helper."""
from __future__ import annotations

import json
import random
import ssl
import string
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable

VERSION = "1.0.0"
UA = f"BriskOSINT/{VERSION} (+authorized-recon)"

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    detail: str = ""
    evidence: Any = None

    def to_dict(self) -> dict:
        return asdict(self)


class Result:
    """What a module returns: free-form data plus a list of findings."""

    def __init__(self, module: str):
        self.module = module
        self.data: dict[str, Any] = {}
        self.findings: list[Finding] = []
        self.error: str | None = None
        self.elapsed: float = 0.0

    def add(self, severity: str, title: str, detail: str = "", evidence: Any = None) -> None:
        assert severity in SEV_ORDER, severity
        self.findings.append(Finding(self.module, severity, title, detail, evidence))


@dataclass
class Context:
    target: str
    timeout: int = 10
    threads: int = 40
    passive: bool = False          # no DNS brute-force
    active: bool = False           # light exposure probes against the target
    github: str | None = None      # GitHub org/user handle override
    brand: str | None = None       # brand handle override
    wordlist: str | None = None
    max_permutations: int = 2500
    keys: dict[str, str] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Brand label, e.g. 'brisk' for brisk.com."""
        if self.brand:
            return self.brand.lower()
        return self.target.split(".")[0].lower()


def http(url: str, headers: dict | None = None, timeout: int = 10,
         max_bytes: int = 1_500_000, retries: int = 1, verify: bool = True) -> dict:
    """GET a URL. Never raises; returns a dict with ok/status/headers/text/error."""
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    sslctx = None if verify else ssl._create_unverified_context()
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as r:
                return _pack(r, r.status, max_bytes)
        except urllib.error.HTTPError as e:
            return _pack(e, e.code, max_bytes)
        except Exception as e:  # noqa: BLE001 - network errors are data here
            last = e
            time.sleep(0.4 * (attempt + 1))
    return {"ok": False, "status": None, "error": str(last), "headers": {},
            "cookies": [], "text": "", "url": url}


def _pack(r, status: int, max_bytes: int) -> dict:
    body = r.read(max_bytes)
    hdrs = r.headers
    charset = hdrs.get_content_charset() or "utf-8"
    return {
        "ok": 200 <= status < 400,
        "status": status,
        "url": r.geturl() if hasattr(r, "geturl") else "",
        "headers": {k.lower(): v for k, v in hdrs.items()},
        "cookies": hdrs.get_all("Set-Cookie") or [],
        "text": body.decode(charset, "replace"),
        "error": None,
    }


def http_json(url: str, **kw) -> Any:
    r = http(url, **kw)
    if r["status"] and 200 <= r["status"] < 300:
        try:
            return json.loads(r["text"])
        except ValueError:
            return None
    return None


def rand_label(n: int = 14) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def pmap(fn: Callable, items: Iterable, threads: int = 40) -> list[tuple[Any, Any]]:
    """Run fn over items in a thread pool; returns [(item, result_or_None)]."""
    items = list(items)
    out: list[tuple[Any, Any]] = []
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(items)))) as ex:
        futs = {ex.submit(fn, i): i for i in items}
        for f in as_completed(futs):
            try:
                out.append((futs[f], f.result()))
            except Exception:  # noqa: BLE001
                out.append((futs[f], None))
    return out


def risk_score(findings: list[Finding]) -> dict:
    penalty = sum(SEV_WEIGHT[f.severity] for f in findings)
    value = max(0, 100 - penalty)
    grade = "A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65 else "D" if value >= 45 else "F"
    return {"value": value, "grade": grade, "penalty": penalty}
