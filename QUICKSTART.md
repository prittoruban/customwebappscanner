# Quick Start Guide

## 🚀 Get Started in 3 Minutes

### Step 1: Install Dependencies

```bash
cd scanner
pip install -r requirements.txt
```

### Step 2: Run Your First Scan

**Scan for XSS vulnerabilities:**
```bash
python main.py -u http://testphp.vulnweb.com --xss
```

**Scan for all vulnerabilities:**
```bash
python main.py -u http://testphp.vulnweb.com --xss --sqli --csrf
```

### Step 3: View Reports

**Generate HTML report:**
```bash
python main.py -u http://testphp.vulnweb.com --xss --report html
```

Reports are saved to `scanner/reports/` directory.

---

## 📖 Common Commands

### Basic Scans

```bash
# XSS only
python main.py -u http://example.com --xss

# SQLi only
python main.py -u http://example.com --sqli

# CSRF only
python main.py -u http://example.com --csrf

# All vulnerability types
python main.py -u http://example.com --xss --sqli --csrf
```

### Performance Options

```bash
# Use 10 threads (faster)
python main.py -u http://example.com --xss --threads 10

# Deep crawl (depth 5)
python main.py -u http://example.com --xss --depth 5

# Shallow crawl (depth 1)
python main.py -u http://example.com --xss --depth 1
```

### Report Options

```bash
# HTML report
python main.py -u http://example.com --xss --report html

# JSON report
python main.py -u http://example.com --xss --report json

# Both HTML and JSON
python main.py -u http://example.com --xss --report both

# Console only (default)
python main.py -u http://example.com --xss
```

### Debugging

```bash
# Verbose output
python main.py -u http://example.com --xss -v

# Show help
python main.py --help
```

---

## 🎯 Safe Testing Targets

Practice on these intentionally vulnerable applications:

- **http://testphp.vulnweb.com** (Online test site)
- **DVWA** (Download: http://www.dvwa.co.uk/)
- **OWASP Juice Shop** (https://owasp.org/www-project-juice-shop/)

---

## ⚠️ Important Reminders

1. **Only test applications you own or have permission to test**
2. **Never use on production systems without authorization**
3. **Read the full README.md for detailed documentation**

---

## 🆘 Troubleshooting

### "No forms found"
- The target may not have any forms
- Try increasing crawl depth: `--depth 3`
- Check if the target URL is accessible

### "Connection timeout"
- Target may be slow or blocking requests
- Check your internet connection
- Try a different target

### "Import errors"
- Ensure dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python --version` (need 3.10+)

---

## 📚 Next Steps

1. Read the full [README.md](README.md) for complete documentation
2. Check [examples.py](examples.py) for programmatic usage
3. Customize payloads in `scanner/payloads/` directory
4. Modify `scanner/config.py` for advanced settings

---

**Happy (ethical) hacking! 🛡️**
