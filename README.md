<p align="center"><img src="assets/logo.png" alt="Brisk OSINT" width="640"></p>

# Brisk OSINT

External attack-surface and brand-protection intelligence framework.
**Developed by Eng. Malek Al-astal.**

Give it a domain; it maps the organisation's public footprint, scores the risk, and writes a branded report (HTML dashboard + JSON + Markdown). Runs on the Python standard library alone (`dnspython` is optional and faster). No API keys required.

> For assets you own or are authorised to assess. Everything it collects is publicly available data.

## Install & run

```bash
cd brisk-osint
pip install -e .            # or:  pip install -e ".[fast]"   (adds dnspython)
brisk-osint brisk.com       # or: python3 -m brisk_osint brisk.com
```

```bash
brisk-osint brisk.com -p quick                  # fast: whois, dns, email, web
brisk-osint brisk.com --active                  # + light probes for exposed .git/.env/phpinfo...
brisk-osint brisk.com --passive                 # no DNS brute-force
brisk-osint brisk.com -m subdomains,typosquat   # pick modules
brisk-osint brisk.com --github briskhq --brand brisk
brisk-osint a.com b.com -f html -o reports/     # several targets
brisk-osint --list-modules
```

Optional environment variables: `GITHUB_TOKEN` (enables code search for leaked references), `SHODAN_API_KEY` (richer service banners).

## Modules

| Module | What it does |
|---|---|
| `whois` | RDAP registrar, dates, transfer lock, DNSSEC, expiry warnings |
| `dns` | A/AAAA/MX/NS/TXT/SOA/CAA, mail & DNS providers, SaaS footprint from TXT verifications |
| `email` | SPF / DMARC / DKIM / MTA-STS / BIMI analysis and spoofability score |
| `web` | Security headers, cookies, TLS certificate, tech stack, robots.txt, security.txt (+ exposure probes with `--active`) |
| `subdomains` | crt.sh + OTX + HackerTarget + DNS brute-force, wildcard filtering, takeover detection, dev/internal host flags |
| `typosquat` | Look-alike domains (typos, homoglyphs, IDN, bit-flips, TLD swaps, keywords), registered ones, mail-capable ones, phishing-page detection |
| `wayback` | Archived URLs: sensitive files, admin/debug paths, parameters, old hosts |
| `github` | Org repositories; with a token, public code referencing your domain/secrets |
| `brands` | Where your brand handle exists or is unclaimed across developer/social platforms |
| `breaches` | Public breaches of the domain (HIBP catalogue) |
| `infra` | IP ownership (RDAP), open ports and potential CVEs (Shodan InternetDB), risky-service flags |

Modules run in parallel; one failing module never stops the scan. If DNS is unreachable the DNS-based modules report an error instead of false "missing record" findings.

## Output

`brisk-reports/<domain>_<timestamp>/` containing `report.html` (dashboard with severity filters and search), `report.json` (full data for pipelines) and `report.md`.

## Development

```bash
python3 -m unittest discover -s tests   # offline tests
python3 tools/make_logo.py              # regenerate assets/logo.svg + logo.png
```

Add a module: create `brisk_osint/modules/foo.py` with `NAME`, `DESC`, `PHASE` and `run(ctx) -> Result`, then register it in `modules/__init__.py`.

---

## بالعربي (باختصار)

أداة OSINT لفحص البصمة الخارجية لأي نطاق وحماية العلامة التجارية: النطاقات الفرعية، سجلات البريد (SPF/DMARC)، النطاقات المقلّدة والصفحات المزيفة، المنافذ المكشوفة، التسريبات، وتاريخ الروابط. التشغيل: `brisk-osint brisk.com` والتقرير بيطلع HTML + JSON + Markdown بألوان بريسك. للاستخدام على الأصول اللي بتملكها أو معك تصريح بفحصها فقط.
