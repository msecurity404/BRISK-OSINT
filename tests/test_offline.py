"""Offline tests: no network required.  Run: python3 -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brisk_osint import branding, cli  # noqa: E402
from brisk_osint.core import Finding, risk_score  # noqa: E402
from brisk_osint.modules import REGISTRY, email_security, typosquat  # noqa: E402
from brisk_osint.report import write_all  # noqa: E402


class Tests(unittest.TestCase):
    def test_spf_parse(self):
        p = email_security.parse_spf("v=spf1 include:_spf.google.com mx a -all")
        self.assertEqual(p["all"], "-")
        self.assertEqual(p["lookups"], 3)
        self.assertEqual(email_security.parse_spf("v=spf1 ~all")["all"], "~")
        self.assertEqual(email_security.parse_spf("v=spf1 +all")["all"], "+")

    def test_dmarc_parse(self):
        t = email_security.parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.c; pct=100")
        self.assertEqual(t["p"], "reject")

    def test_typosquat(self):
        perms = typosquat.permutations("brisk.com")
        self.assertGreater(len(perms), 100)
        self.assertNotIn("brisk.com", perms)
        self.assertIn("brisk.net", perms)
        self.assertIn("brsk.com", perms)
        self.assertTrue(any(k.startswith("xn--") for k in perms))
        self.assertEqual(typosquat.split_domain("shop.example.co.il"), ("shop.example", "co.il"))

    def test_normalize(self):
        self.assertEqual(cli.normalize_target("https://www.Brisk.com/path"), "brisk.com")
        self.assertTrue(cli.DOMAIN_RE.match("brisk.com"))
        self.assertFalse(cli.DOMAIN_RE.match("not a domain"))

    def test_score(self):
        self.assertEqual(risk_score([])["grade"], "A")
        self.assertEqual(risk_score([Finding("x", "critical", "t")] * 5)["value"], 0)

    def test_registry(self):
        self.assertEqual(len(REGISTRY), 11)
        for m in REGISTRY.values():
            self.assertTrue(callable(m.run) and m.DESC and m.PHASE in (1, 2))

    def test_logo_and_banner(self):
        svg = branding.logo_svg()
        self.assertTrue(svg.startswith("<svg") and svg.rstrip().endswith("</svg>"))
        self.assertIn("Eng. Malek Al-astal", branding.banner("1.0.0", color=False))

    def test_reports(self):
        report = {
            "meta": {"target": "x.com", "finished": "now", "duration": 1, "modules": ["web"], "version": "1"},
            "score": {"value": 70, "grade": "C", "penalty": 30},
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "findings": [{"module": "web", "severity": "high", "title": "<b>x</b>", "detail": "d", "evidence": None}],
            "modules": {"web": {"data": {"a": [1, 2], "b": [{"k": "v"}]}, "error": None, "elapsed": 0.1, "findings": []}},
        }
        with tempfile.TemporaryDirectory() as d:
            paths = write_all(report, d, ["json", "html", "md"])
            self.assertEqual(len(paths), 3)
            html = open(paths[1], encoding="utf-8").read()
            self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)  # XSS-safe
            self.assertNotIn("<b>x</b>", html)


if __name__ == "__main__":
    unittest.main()
