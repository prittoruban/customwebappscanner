# Web Application Vulnerability Scanner v2.0

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776ab.svg?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e.svg)](LICENSE)
[![Scanners: 8](https://img.shields.io/badge/scanners-8-6c8aff.svg)]()
[![Status: Production](https://img.shields.io/badge/status-production-22c55e.svg)]()

> **Disclaimer** — This tool is strictly for educational and authorized security testing. Use only on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## What Is This?

A production-grade CLI vulnerability scanner built in Python that detects 8 classes of web application vulnerabilities, identifies compound attack chains, and generates framework-specific remediation code.

### What Makes It Different

| Feature | Typical Scanners | This Scanner |
|---|---|---|
| XSS Detection | Pattern matching | **Context-aware** — canary injection, detects HTML/attribute/JS/URL/CSS contexts |
| SQLi Detection | Error-string grep | **Differential analysis** — error-based + boolean-blind (response similarity) + time-based (baseline-calibrated) |
| Post-Scan Analysis | Flat finding list | **Vulnerability chain detection** — 7 rules linking compound attack paths (e.g. XSS + missing CSP = CRITICAL) |
| Remediation | Generic description | **Auto-generated fix code** — copy-paste-ready for Flask, Django, Express.js, PHP |

---

## Scan Types

| Flag | Vulnerability | Technique |
|---|---|---|
| `--xss` | Cross-Site Scripting | Context-aware canary probing + reflection verification |
| `--sqli` | SQL Injection | Error-based + Boolean-blind + Time-based with baseline calibration |
| `--csrf` | Cross-Site Request Forgery | Token detection + Shannon entropy analysis + active testing |
| `--ssrf` | Server-Side Request Forgery | Cloud metadata, internal IP, scheme tricks (30+ payloads) |
| `--lfi` | Local File Inclusion | Path traversal, null byte, double encoding, PHP wrappers |
| `--cmdi` | Command Injection / RCE | Output-based + blind time-based detection |
| `--redirect` | Open Redirect | Location header, meta refresh, JS redirect analysis |
| `--headers` | Security Headers & Cookies | CSP, CORS, HSTS, cookie flags (passive scan) |
| `--all` | **All of the above** | Enables every scanner |

---

## Quick Start

```bash
# 1. Clone & enter
git clone <repo-url> && cd customwebappscanner

# 2. Create venv and install
python3 -m venv .venv && source .venv/bin/activate
pip install -r scanner/requirements.txt

# 3. Run a full scan
cd scanner
python3 main.py -u http://testphp.vulnweb.com --all

# 4. Generate an HTML report with Django remediation
python3 main.py -u http://testphp.vulnweb.com --all --framework python_django --report html
```

---

## CLI Reference

```
usage: main.py [-h] -u URL [--all] [--xss] [--sqli] [--csrf] [--ssrf]
               [--lfi] [--cmdi] [--redirect] [--headers]
               [--depth DEPTH] [--threads THREADS] [--payload-dir DIR]
               [--framework {python_flask,python_django,javascript_express,php}]
               [--report {html,json,both}] [-v]
```

### Required

| Argument | Description |
|---|---|
| `-u`, `--url` | Target URL (must start with `http://` or `https://`) |

### Scan Selection

| Argument | Default | Description |
|---|---|---|
| `--all` | off | Enable all 8 scan types |
| `--xss` | off | XSS scan |
| `--sqli` | off | SQL Injection scan |
| `--csrf` | off | CSRF scan |
| `--ssrf` | off | SSRF scan |
| `--lfi` | off | LFI / Path Traversal scan |
| `--cmdi` | off | Command Injection scan |
| `--redirect` | off | Open Redirect scan |
| `--headers` | off | Security Headers (passive) |

### Options

| Argument | Default | Description |
|---|---|---|
| `--depth` | `2` | Maximum crawl depth (0–10) |
| `--threads` | `5` | Concurrent scan threads (1–50) |
| `--payload-dir` | `scanner/payloads/` | Custom payload directory |
| `--framework` | `python_flask` | Remediation code target: `python_flask`, `python_django`, `javascript_express`, `php` |
| `--report` | `console` | Output format: `html`, `json`, `both` |
| `-v` | off | Verbose debug logging |

### Examples

```bash
# XSS + SQLi only, 10 threads, HTML report
python3 main.py -u http://example.com --xss --sqli --threads 10 --report html

# Full scan with deep crawl
python3 main.py -u http://example.com --all --depth 5

# SSRF + Headers check with Express.js remediation
python3 main.py -u http://example.com --ssrf --headers --framework javascript_express

# All scans, all reports
python3 main.py -u http://example.com --all --report both
```

---

## Output Formats

### Console (default)

Severity-sorted findings table with CWE/OWASP references, chain links, and a sample remediation code block.

### HTML (`--report html`)

Dark-themed responsive report with:
- Severity stat cards + risk score
- Detailed findings table (CWE, OWASP, confidence)
- Vulnerability chain section
- Remediation code blocks per finding

Saved to `scanner/reports/scan_report_<timestamp>.html`

### JSON (`--report json`)

Machine-readable output for CI/CD integration. Full schema includes all 18 Finding fields, scan metadata, and statistics.

Saved to `scanner/reports/scan_report_<timestamp>.json`

---

## Project Structure

```
customwebappscanner/
├── .gitignore
├── README.md                      ← You are here
├── docs/
│   ├── ARCHITECTURE.md            ← System design & data flow
│   ├── API.md                     ← Module-level API reference
│   └── CONTRIBUTING.md            ← Development workflow
│
└── scanner/                       ← Main package
    ├── main.py                    ← CLI entry point
    ├── config.py                  ← Global configuration
    ├── requirements.txt           ← Python dependencies
    │
    ├── models/                    ← Shared data models
    │   ├── __init__.py
    │   └── finding.py             ← Finding, ScanResult, SeverityLevel
    │
    ├── crawler/                   ← Web crawling
    │   ├── __init__.py
    │   └── crawler.py             ← BFS crawler + form extraction
    │
    ├── scanner/                   ← Vulnerability scanners (8 modules)
    │   ├── __init__.py
    │   ├── base.py                ← BaseScanner ABC
    │   ├── xss.py                 ← Context-aware XSS
    │   ├── sqli.py                ← Differential SQLi
    │   ├── csrf.py                ← CSRF + entropy analysis
    │   ├── ssrf.py                ← SSRF scanner
    │   ├── lfi.py                 ← LFI / path traversal
    │   ├── cmdi.py                ← Command injection / RCE
    │   ├── redirect.py            ← Open redirect
    │   └── headers.py             ← Security headers (passive)
    │
    ├── engine/                    ← Execution & analysis
    │   ├── __init__.py
    │   ├── executor.py            ← ThreadPool executor
    │   ├── chain_detector.py      ← Vulnerability chain detection
    │   └── remediation.py         ← Auto-remediation code gen
    │
    ├── reporter/                  ← Report generation
    │   ├── __init__.py
    │   ├── report.py              ← Console / HTML / JSON
    │   └── templates/
    │       └── report.html        ← Jinja2 dark-themed template
    │
    ├── payloads/                  ← Attack payload files
    │   ├── xss.txt
    │   ├── sqli.txt
    │   ├── ssrf.txt
    │   ├── lfi.txt
    │   ├── cmdi.txt
    │   └── redirect.txt
    │
    ├── utils/                     ← Shared utilities
    │   ├── __init__.py
    │   ├── http.py                ← HTTP client (rate limiting, retries)
    │   └── logger.py              ← Logging configuration
    │
    ├── reports/                   ← Generated reports (git-ignored)
    └── tests/
        └── test_basic.py          ← 34-test validation suite
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| requests | ≥ 2.31.0 | HTTP client |
| beautifulsoup4 | ≥ 4.12.0 | HTML parsing & form extraction |
| Jinja2 | ≥ 3.1.0 | HTML report templating |
| lxml | ≥ 4.9.0 | Fast HTML parser backend |
| colorama | ≥ 0.4.6 | Colored terminal output |
| urllib3 | ≥ 2.0.0 | URL handling |

Python 3.10+ required.

---

## Running Tests

```bash
cd scanner
python3 tests/test_basic.py
```

34 tests covering: module imports, Finding model, ScanResult properties, all 8 scanner instantiations, chain detection, remediation enrichment, executor lifecycle, report generation, config sanity, and payload file validation.

---

## License

MIT — see [LICENSE](LICENSE) for details.
