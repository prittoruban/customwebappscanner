# Web Application Vulnerability Scanner

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-educational-orange.svg)

## ⚠️ DISCLAIMER

**This tool is for EDUCATIONAL and AUTHORIZED TESTING purposes ONLY.**

- Use only on applications you own or have explicit written permission to test
- Never use on production systems without proper authorization
- Unauthorized testing of web applications is illegal
- The authors assume no liability for misuse of this tool

## 📋 Description

A Python-based CLI vulnerability scanner that detects common web application security issues:

- **XSS (Cross-Site Scripting)**: Reflected and stored XSS vulnerabilities
- **SQLi (SQL Injection)**: Error-based, boolean-based, and time-based SQL injection
- **CSRF (Cross-Site Request Forgery)**: Missing CSRF token protection

### Features

✅ Multi-threaded scanning for improved performance  
✅ Automatic web crawling and form discovery  
✅ Customizable payload files  
✅ Multiple report formats (HTML, JSON, Console)  
✅ Configurable crawl depth and thread count  
✅ Clean, modular architecture  
✅ Comprehensive logging with verbosity control  

## 🏗️ Architecture

```
scanner/
├── main.py                     # CLI entry point
├── config.py                   # Configuration and defaults
├── crawler/                    # Web crawling module
│   ├── __init__.py
│   └── crawler.py
├── scanner/                    # Vulnerability detection modules
│   ├── __init__.py
│   ├── xss.py                  # XSS scanner
│   ├── sqli.py                 # SQLi scanner
│   └── csrf.py                 # CSRF scanner
├── engine/                     # Multi-threaded execution engine
│   ├── __init__.py
│   └── executor.py
├── reporter/                   # Report generation
│   ├── __init__.py
│   ├── report.py
│   └── templates/
│       └── report.html         # Jinja2 template
├── payloads/                   # Attack payload files
│   ├── xss.txt
│   └── sqli.txt
├── utils/                      # Utility modules
│   ├── http.py                 # HTTP client wrapper
│   └── logger.py               # Logging configuration
└── requirements.txt
```

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. **Clone or download this repository:**

```bash
cd scanner
```

2. **Create a virtual environment (recommended):**

```bash
python -m venv venv

# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

## 💻 Usage

### Basic Usage

Scan a target URL for all vulnerability types:

```bash
python main.py -u http://testphp.vulnweb.com --xss --sqli --csrf
```

### Common Examples

**XSS scan only:**
```bash
python main.py -u http://example.com --xss
```

**SQLi and CSRF scan with 10 threads:**
```bash
python main.py -u http://example.com --sqli --csrf --threads 10
```

**Full scan with HTML report:**
```bash
python main.py -u http://example.com --xss --sqli --csrf --report html
```

**Deep crawl with JSON report:**
```bash
python main.py -u http://example.com --xss --depth 5 --report json
```

**Verbose logging for debugging:**
```bash
python main.py -u http://example.com --xss --sqli -v
```

### Command-Line Options

```
Required Arguments:
  -u URL, --url URL            Target URL to scan

Scan Types:
  --xss                        Enable XSS scanning
  --sqli                       Enable SQL injection scanning
  --csrf                       Enable CSRF scanning

Crawler Options:
  --depth N                    Maximum crawl depth (default: 2)

Scanner Options:
  --threads N                  Number of concurrent threads (default: 5)
  --payload-dir PATH           Custom payload directory

Report Options:
  --report {html,json,both}    Report format (default: console)

Other:
  -v, --verbose                Enable verbose/debug logging
  -h, --help                   Show help message
```

## 📊 Output

### Console Output

The scanner provides real-time progress updates and a summary report:

```
╔═══════════════════════════════════════════════════════════════════╗
║   🔒 Web Application Vulnerability Scanner v1.0                  ║
╚═══════════════════════════════════════════════════════════════════╝

🕷️  Crawling http://example.com...
✓ Crawl complete. Found 5 form(s) across 10 page(s)

🔍 Starting vulnerability scan with 5 thread(s)...
✓ Scan complete. Found 3 vulnerabilities

VULNERABILITY SCAN REPORT
======================================================================
Target: http://example.com
Total Vulnerabilities Found: 3

By Severity:
  HIGH: 2
  MEDIUM: 1
```

### HTML Report

Beautiful, styled HTML reports with:
- Summary statistics and risk scores
- Vulnerability details table
- Severity color-coding
- Evidence snippets

Reports are saved to `scanner/reports/scan_report_TIMESTAMP.html`

### JSON Report

Machine-readable JSON format for integration with other tools:

```json
{
  "scan_info": {
    "target_url": "http://example.com",
    "scan_date": "2026-01-06T12:00:00"
  },
  "statistics": {
    "total_vulnerabilities": 3,
    "by_type": {"XSS": 2, "CSRF": 1}
  },
  "findings": [...]
}
```

## 🎯 Testing Targets

**Safe testing environments:**

- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [bWAPP](http://www.itsecgames.com/)
- [Mutillidae](https://github.com/webpwnized/mutillidae)

**Online testing sites:**
- http://testphp.vulnweb.com/
- http://demo.testfire.net/

## 🔧 Customization

### Custom Payloads

Edit payload files in `scanner/payloads/`:
- `xss.txt` - XSS test vectors
- `sqli.txt` - SQL injection payloads

Each line is a separate payload. Lines starting with `#` are comments.

### Configuration

Modify `scanner/config.py` to adjust:
- Timeouts and retry settings
- Thread limits
- Crawl parameters
- Detection patterns

## 🛡️ Security Considerations

This tool performs **active** security testing which may:
- Generate suspicious traffic
- Trigger security monitoring systems
- Modify application state (CSRF tests)
- Create load on target servers

**Always ensure you have proper authorization before scanning.**

## 📚 How It Works

### 1. Crawling Phase
- Starts from provided URL
- Follows links within same domain
- Extracts forms with all input fields
- Respects configured depth limit

### 2. Scanning Phase
- **XSS**: Injects payloads into inputs, checks for reflection
- **SQLi**: Tests for syntax errors, time delays, boolean conditions
- **CSRF**: Identifies POST forms lacking CSRF tokens

### 3. Reporting Phase
- Aggregates findings by severity
- Generates reports in requested formats
- Provides actionable vulnerability details

## 🤝 Contributing

This is an educational demo project. Improvements welcome:
- Additional vulnerability types (XXE, SSRF, etc.)
- Enhanced detection accuracy
- Better payload libraries
- Performance optimizations

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

Created for educational and security research purposes.

## 🔗 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

**Remember: With great power comes great responsibility. Use ethically!** 🛡️
