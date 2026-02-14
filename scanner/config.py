"""
Global configuration and default settings for the vulnerability scanner.

Defines paths, timeouts, threading limits, and security boundaries.
All modules should import settings from here rather than hardcoding values.
"""

import os
from pathlib import Path

# ============================================================================
# PROJECT PATHS
# ============================================================================

# Get the root directory of the scanner project
PROJECT_ROOT = Path(__file__).parent
PAYLOAD_DIR = PROJECT_ROOT / "payloads"
REPORT_DIR = PROJECT_ROOT / "reports"
TEMPLATE_DIR = PROJECT_ROOT / "reporter" / "templates"

# Ensure report directory exists
REPORT_DIR.mkdir(exist_ok=True)

# ============================================================================
# PAYLOAD FILES
# ============================================================================

XSS_PAYLOAD_FILE = "xss.txt"
SQLI_PAYLOAD_FILE = "sqli.txt"
SSRF_PAYLOAD_FILE = "ssrf.txt"
LFI_PAYLOAD_FILE = "lfi.txt"
CMDI_PAYLOAD_FILE = "cmdi.txt"
REDIRECT_PAYLOAD_FILE = "redirect.txt"

# Maximum payloads per input field (limits scan time)
MAX_PAYLOADS_PER_INPUT = 50

# ============================================================================
# CIRCUIT BREAKER
# ============================================================================

# Number of consecutive failures on a URL before skipping further requests
CIRCUIT_BREAKER_THRESHOLD = 3

# ============================================================================
# HTTP CLIENT SETTINGS
# ============================================================================

# Request timeout in seconds
REQUEST_TIMEOUT = 10

# Maximum number of retries for failed requests
MAX_RETRIES = 3

# User-Agent header to use for requests
USER_AGENT = "VulnScanner/2.0 (Educational Security Scanner)"

# Delay between requests in seconds (rate limiting)
REQUEST_DELAY = 0.0

# Follow redirects
FOLLOW_REDIRECTS = True

# Verify SSL certificates
VERIFY_SSL = False

# ============================================================================
# CRAWLER SETTINGS
# ============================================================================

# Maximum crawl depth (levels to traverse from starting URL)
DEFAULT_CRAWL_DEPTH = 2

# Maximum number of URLs to crawl per session
MAX_CRAWL_URLS = 100

# Maximum number of forms to extract per page
MAX_FORMS_PER_PAGE = 20

# ============================================================================
# SCANNER SETTINGS
# ============================================================================

# Default thread count for parallel scanning
DEFAULT_THREADS = 5

# Maximum number of threads allowed
MAX_THREADS = 50

# Time-based SQL injection delay threshold (seconds)
SQLI_TIME_THRESHOLD = 5

# Time-based SQLi baseline measurements
SQLI_BASELINE_SAMPLES = 3

# Maximum payload size (characters)
MAX_PAYLOAD_SIZE = 1000

# ============================================================================
# VULNERABILITY DETECTION SETTINGS
# ============================================================================

# XSS: Patterns to detect reflected payloads in responses
XSS_REFLECTION_PATTERNS = [
    '<script>',
    'alert(',
    'onerror=',
    'onload=',
    'javascript:',
    'onfocus=',
    'onmouseover=',
    '<svg',
    '<img',
]

# XSS: Context detection patterns
XSS_CONTEXTS = {
    'html_tag': r'<[^>]*{CANARY}[^>]*>',
    'html_attribute': r'["\'][^"\']*{CANARY}[^"\']*["\']',
    'html_body': r'>[^<]*{CANARY}[^<]*<',
    'javascript': r'<script[^>]*>[^<]*{CANARY}[^<]*</script>',
    'url': r'(href|src|action)=["\'][^"\']*{CANARY}',
    'css': r'style=["\'][^"\']*{CANARY}',
}

# SQLi: Error patterns indicating SQL injection vulnerability
SQLI_ERROR_PATTERNS = [
    r'SQL syntax.*?MySQL',
    r'Warning.*?mysql_',
    r'Warning.*?mysqli_',
    r'MySQLSyntaxErrorException',
    r'valid MySQL result',
    r'ORA-\d{5}',
    r'Oracle.*?Driver',
    r'PostgreSQL.*?ERROR',
    r'Warning.*?pg_',
    r'SQLite.*?(?:error|warning)',
    r'ODBC.*?Driver',
    r'JET Database Engine',
    r'Access Database Engine',
    r'Unclosed quotation mark',
    r'quoted string not properly terminated',
    r'Microsoft.*?SQL Server',
    r'Syntax error.*?in query expression',
    r'Unexpected end of command in statement',
    r'com\.microsoft\.sqlserver\.jdbc',
    r'org\.postgresql\.util\.PSQLException',
    r'com\.mysql\.jdbc\.exceptions',
]

# CSRF: Token field names to look for (exact matches only)
CSRF_TOKEN_NAMES = [
    'csrf_token',
    'csrftoken',
    'csrf',
    '_token',
    'authenticity_token',
    'anti_csrf_token',
    'csrfmiddlewaretoken',
    '__requestverificationtoken',
    'antiforgery',
    'xsrf_token',
    'xsrf-token',
]

# CSRF: Patterns in hidden field names that indicate CSRF tokens
CSRF_TOKEN_PATTERNS = [
    'csrf',
    'xsrf',
    'antiforgery',
    'authenticity',
    'request_verification',
    'anti_csrf',
]

# ============================================================================
# SECURITY HEADERS
# ============================================================================

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'severity': 'HIGH',
        'description': 'HSTS not configured - vulnerable to protocol downgrade attacks',
        'remediation': 'Add Strict-Transport-Security header with max-age >= 31536000',
    },
    'Content-Security-Policy': {
        'severity': 'MEDIUM',
        'description': 'CSP not configured - increased XSS risk',
        'remediation': 'Implement Content-Security-Policy header with strict directives',
    },
    'X-Content-Type-Options': {
        'severity': 'LOW',
        'description': 'MIME sniffing protection missing',
        'remediation': 'Add X-Content-Type-Options: nosniff header',
    },
    'X-Frame-Options': {
        'severity': 'MEDIUM',
        'description': 'Clickjacking protection missing',
        'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header',
    },
    'X-XSS-Protection': {
        'severity': 'LOW',
        'description': 'Browser XSS filter not enabled',
        'remediation': 'Add X-XSS-Protection: 1; mode=block header',
    },
    'Referrer-Policy': {
        'severity': 'LOW',
        'description': 'Referrer policy not set',
        'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin header',
    },
    'Permissions-Policy': {
        'severity': 'LOW',
        'description': 'Permissions policy not configured',
        'remediation': 'Add Permissions-Policy header to restrict browser features',
    },
}

# Dangerous cookie flags to check
COOKIE_SECURITY_FLAGS = {
    'secure': 'Cookie not marked Secure - transmitted over HTTP',
    'httponly': 'Cookie not marked HttpOnly - accessible via JavaScript',
    'samesite': 'Cookie missing SameSite attribute - CSRF risk',
}

# ============================================================================
# REPORTING SETTINGS
# ============================================================================

# Severity levels for findings (weight for risk scoring)
SEVERITY_LEVELS = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}

# Report output formats
REPORT_FORMATS = ['html', 'json', 'both']

# CWE mappings for vulnerability types
CWE_MAPPINGS = {
    'XSS': 'CWE-79',
    'SQLi': 'CWE-89',
    'CSRF': 'CWE-352',
    'SSRF': 'CWE-918',
    'LFI': 'CWE-98',
    'RCE': 'CWE-78',
    'Open Redirect': 'CWE-601',
    'Security Headers': 'CWE-693',
}

# OWASP Top 10 2021 mappings
OWASP_MAPPINGS = {
    'XSS': 'A03:2021 - Injection',
    'SQLi': 'A03:2021 - Injection',
    'CSRF': 'A01:2021 - Broken Access Control',
    'SSRF': 'A10:2021 - Server-Side Request Forgery',
    'LFI': 'A01:2021 - Broken Access Control',
    'RCE': 'A03:2021 - Injection',
    'Open Redirect': 'A01:2021 - Broken Access Control',
    'Security Headers': 'A05:2021 - Security Misconfiguration',
}


# ============================================================================
# SAFETY LIMITS (Educational/Demo Mode)
# ============================================================================

# Maximum number of payloads to test per input field
MAX_PAYLOADS_PER_INPUT = 50

# Delay between requests (seconds) to avoid overwhelming target
REQUEST_DELAY = 0.1

# ============================================================================
# PAYLOAD FILE NAMES
# ============================================================================

XSS_PAYLOAD_FILE = "xss.txt"
SQLI_PAYLOAD_FILE = "sqli.txt"

# ============================================================================
# LOGGING
# ============================================================================

LOG_FORMAT = '[%(asctime)s] %(levelname)s [%(name)s] %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
