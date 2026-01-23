"""
Global configuration and default settings for the vulnerability scanner.

Defines paths, timeouts, threading limits, and security boundaries.
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
# HTTP CLIENT SETTINGS
# ============================================================================

# Request timeout in seconds
REQUEST_TIMEOUT = 10

# Maximum number of retries for failed requests
MAX_RETRIES = 3

# User-Agent header to use for requests
USER_AGENT = "VulnScanner/1.0 (Educational Demo)"

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
MAX_THREADS = 20

# Time-based SQL injection delay threshold (seconds)
SQLI_TIME_THRESHOLD = 5

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
]

# SQLi: Error patterns indicating SQL injection vulnerability
SQLI_ERROR_PATTERNS = [
    'SQL syntax',
    'mysql_fetch',
    'mysqli',
    'ORA-',
    'PostgreSQL',
    'Warning: pg_',
    'SQLite',
    'ODBC',
    'JET Database',
    'Access Database',
    'Unclosed quotation',
    'quoted string not properly terminated',
]

# CSRF: Token field names to look for
CSRF_TOKEN_NAMES = [
    'csrf_token',
    'csrftoken',
    'csrf',
    'token',
    '_token',
    'authenticity_token',
    'anti_csrf_token',
]

# ============================================================================
# REPORTING SETTINGS
# ============================================================================

# Severity levels for findings
SEVERITY_LEVELS = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}

# Report output formats
REPORT_FORMATS = ['html', 'json', 'both']

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
