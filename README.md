<p align="center">
  <img src="assets/logo.png" alt="BRISK OSINT Logo" width="520">
</p>

<h1 align="center">BRISK OSINT</h1>

<p align="center">
  <strong>External Attack Surface Intelligence & Brand Protection Framework</strong>
</p>

<p align="center">
  <a href="https://github.com/msecurity404/BRISK-OSINT">
    <img src="https://img.shields.io/badge/Project-BRISK%20OSINT-gold" alt="Project">
  </a>
  <img src="https://img.shields.io/badge/Version-1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.9%2B-green" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-lightgrey" alt="Platform">
</p>

---

## Overview

**BRISK OSINT** is a Python-based Open Source Intelligence (OSINT) framework designed to help security researchers and authorized security teams assess an organization's external digital footprint.

It combines domain intelligence, DNS reconnaissance, email security analysis, subdomain discovery, brand impersonation checks, infrastructure intelligence, and historical URL analysis into one command-line tool.

BRISK OSINT generates structured security reports in HTML, JSON, and Markdown formats.

**Developed by Eng. Malek Al-astal**

**GitHub:** https://github.com/msecurity404

---

## Key Features

- Domain and WHOIS/RDAP intelligence.
- DNS record and infrastructure discovery.
- Email security assessment: SPF, DMARC, DKIM, MTA-STS, and BIMI.
- Subdomain discovery and takeover indicators.
- Website technology and security-header fingerprinting.
- Look-alike domain and typosquatting detection.
- Historical URL intelligence through Wayback Machine.
- GitHub organization and public code intelligence.
- Brand handle discovery across supported platforms.
- Public breach catalogue checks.
- Public IP and infrastructure intelligence.
- Document and image metadata analysis.
- Risk scoring and scan history comparison.
- HTML, JSON, and Markdown report generation.

---

## Installation

### Requirements

- Python 3.9 or newer.
- Git.
- Internet connection for online intelligence modules.

### Termux (Android)

Update packages:

```bash
pkg update -y && pkg upgrade -y
pkg install python git -y
```

Clone the repository:

```bash
git clone https://github.com/msecurity404/BRISK-OSINT.git
cd BRISK-OSINT
```

Install:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[fast]"
```

Run:

```bash
brisk-osint
```

If the command is unavailable, use:

```bash
python -m brisk_osint
```

### Linux

```bash
git clone https://github.com/msecurity404/BRISK-OSINT.git
cd BRISK-OSINT

python3 -m pip install -e ".[fast]"
brisk-osint
```

### Optional dependency

The framework uses Python's standard library for its core functionality. The optional `fast` extra installs `dnspython` for additional DNS functionality.

```bash
python -m pip install dnspython
```

---

## Usage

### Interactive Menu

Start BRISK OSINT without arguments:

```bash
brisk-osint
```

The interactive menu provides:

1. Domain Intelligence
2. DNS & WHOIS
3. Email Security
4. IP Intelligence
5. Technology Detection
6. Metadata Analysis
7. Look-alike Domains
8. Brand Handles
9. Scan History
0. Exit

### Domain Intelligence

Run a full scan:

```bash
brisk-osint example.com
```

Run a quick scan:

```bash
brisk-osint example.com -p quick
```

Run a standard scan:

```bash
brisk-osint example.com -p standard
```

Run a full scan explicitly:

```bash
brisk-osint example.com -p full
```

### Select Specific Modules

```bash
brisk-osint example.com -m whois,dns,email,web
```

Scan subdomains and look-alike domains:

```bash
brisk-osint example.com -m subdomains,typosquat
```

List available modules:

```bash
brisk-osint --list-modules
```

Exclude modules:

```bash
brisk-osint example.com -x breaches,github
```

### Passive and Active Options

Passive mode skips DNS brute-force:

```bash
brisk-osint example.com --passive
```

Active mode enables light exposure probes against the target, including checks for paths such as `.git` and `.env`:

```bash
brisk-osint example.com --active
```

Only use active checks on systems you own or have explicit permission to assess.

### Multiple Domains

```bash
brisk-osint example.com example.org
```

### IP Intelligence

```bash
brisk-osint --ip 8.8.8.8
```

### Metadata Analysis

Analyze a local file or directory:

```bash
brisk-osint --metadata ./documents
```

### Scan History

```bash
brisk-osint --history
```

Disable history recording for a scan:

```bash
brisk-osint example.com --no-history
```

---

## Modules

| Module | Description |
|---|---|
| `whois` | RDAP registration information, registrar, dates, DNSSEC, and expiry indicators. |
| `dns` | A, AAAA, MX, NS, TXT, SOA, and CAA records, plus DNS and mail provider intelligence. |
| `email` | SPF, DMARC, DKIM, MTA-STS, BIMI, and email spoofing-related checks. |
| `web` | HTTP security headers, cookies, TLS certificate information, technology detection, robots.txt, and security.txt. |
| `subdomains` | Subdomain discovery, DNS checks, wildcard filtering, and takeover indicators. |
| `typosquat` | Look-alike domains, common variations, registration checks, and phishing-page indicators. |
| `wayback` | Historical URLs and potentially sensitive archived paths. |
| `github` | GitHub organization repositories and public code searches when a token is configured. |
| `brands` | Brand-handle presence checks across supported online platforms. |
| `breaches` | Public breach catalogue checks for a domain. |
| `infra` | IP ownership, infrastructure information, exposed services, and potential vulnerability indicators. |
| `metadata` | Metadata extraction from supported public documents and local files. |

---

## Configuration

BRISK OSINT does not require API keys for its basic operation.

Optional environment variables can enable additional intelligence:

### GitHub Token

Used for authenticated GitHub code search capabilities:

```bash
export GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
```

### Shodan API Key

Used for richer infrastructure and service intelligence:

```bash
export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
```

Keep API keys private. Never commit tokens, passwords, or secret configuration files to GitHub.

---

## Reports

Reports are saved in:

```text
brisk-reports/
```

Each scan creates a timestamped directory:

```text
brisk-reports/
└── example.com_YYYYMMDD-HHMMSS/
    ├── report.html
    ├── report.json
    └── report.md
```

### Report Formats

| File | Purpose |
|---|---|
| `report.html` | Interactive HTML dashboard with severity filters and search. |
| `report.json` | Structured scan data for integrations and automation. |
| `report.md` | Human-readable Markdown report. |

Choose report formats:

```bash
brisk-osint example.com -f html
```

```bash
brisk-osint example.com -f json,md
```

Choose an output directory:

```bash
brisk-osint example.com -o reports/
```

BRISK OSINT can compare a new domain scan with the previous scan and identify new and resolved findings.

---

## Advanced Options

| Option | Description |
|---|---|
| `-p, --profile` | Select `quick`, `standard`, or `full`. |
| `-m, --modules` | Select comma-separated modules. |
| `-x, --exclude` | Exclude selected modules. |
| `--list-modules` | Display registered modules. |
| `--active` | Enable light exposure probes. |
| `--passive` | Skip DNS brute-force. |
| `--ip` | Investigate a public IP address. |
| `--metadata` | Analyze a local file or directory. |
| `--history` | Display previous scans. |
| `--no-history` | Disable scan history recording. |
| `-o, --output` | Set report output directory. |
| `-f, --format` | Select `json`, `html`, and/or `md`. |
| `-t, --threads` | Set worker thread count. |
| `--timeout` | Set network timeout in seconds. |
| `--wordlist` | Provide an additional subdomain wordlist. |
| `--github` | Specify a GitHub organization or user. |
| `--brand` | Specify a brand label. |
| `--max-permutations` | Set the maximum look-alike permutations. |
| `--no-color` | Disable terminal colors. |
| `--no-banner` | Hide the startup banner. |
| `-q, --quiet` | Reduce terminal output. |
| `--version` | Display the installed version. |
| `-h, --help` | Display command help. |

---

## Development

Run offline tests:

```bash
python -m unittest discover -s tests
```

Regenerate logo assets:

```bash
python tools/make_logo.py
```

### Adding a Module

Create a Python module inside:

```text
brisk_osint/modules/
```

A module should expose:

- `NAME`
- `DESC`
- `PHASE`
- `run(ctx)`

Register the module in:

```text
brisk_osint/modules/__init__.py
```

---

## Project Structure

```text
BRISK-OSINT/
├── assets/
│   ├── logo.png
│   └── logo.svg
├── brisk_osint/
│   ├── modules/
│   ├── cli.py
│   ├── core.py
│   ├── report.py
│   ├── history.py
│   ├── ipintel.py
│   ├── dnsutil.py
│   ├── branding.py
│   └── ui.py
├── tests/
├── tools/
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Legal & Responsible Use

BRISK OSINT is intended for legitimate security research, defensive reconnaissance, and authorized security assessments.

- Only scan domains, IP addresses, and systems you own or have explicit permission to assess.
- Respect applicable laws, privacy requirements, and third-party service terms.
- Active probes should only be used within an authorized scope.
- Findings are indicators that require verification; they are not a guarantee that a vulnerability exists.
- The developer is not responsible for misuse of this software.

---

## Author

**Eng. Malek Al-astal**  
Founder & CEO — TechNova  
Cybersecurity & Information Security Engineering

GitHub: [@msecurity404](https://github.com/msecurity404)

Project: [BRISK OSINT](https://github.com/msecurity404/BRISK-OSINT)

---

<p align="center">
  <strong>BRISK OSINT</strong><br>
  Intelligence. Visibility. Security.
</p>
