"""
Auto-Remediation Code Generator.

Generates language-specific remediation code snippets for each vulnerability type.
This is a unique differentiator — instead of just reporting problems,
the scanner provides copy-paste-ready fix code.
"""

from typing import Dict, List, Optional
from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)

# Remediation templates organized by vulnerability type and language/framework
REMEDIATION_TEMPLATES = {
    'XSS': {
        'python_flask': {
            'title': 'Flask XSS Prevention',
            'code': '''# Flask: Auto-escaping is enabled by default in Jinja2 templates
# Ensure you're not using |safe filter on user input

# BAD - vulnerable to XSS:
# return render_template('page.html', name=request.args.get('name'))
# In template: {{ name|safe }}  <-- NEVER use |safe with user input

# GOOD - properly escaped:
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Option 1: Let Jinja2 auto-escape (default)
    return render_template('results.html', query=query)
    # Option 2: Manual escaping
    # safe_query = escape(query)
    # return f"Results for: {safe_query}"
''',
        },
        'python_django': {
            'title': 'Django XSS Prevention',
            'code': '''# Django auto-escapes template variables by default.
# Ensure you're not using |safe or {% autoescape off %}

# BAD:
# {{ user_input|safe }}
# {% autoescape off %}{{ user_input }}{% endautoescape %}

# GOOD:
# {{ user_input }}  {# Auto-escaped by default #}

# For JavaScript contexts, use json_script filter:
# {{ user_data|json_script:"data-id" }}

# In views, use django.utils.html.escape for manual escaping:
from django.utils.html import escape
safe_input = escape(request.GET.get('q', ''))
''',
        },
        'javascript_express': {
            'title': 'Express.js XSS Prevention',
            'code': '''// Use a template engine with auto-escaping (EJS, Pug, Handlebars)
// Install: npm install helmet dompurify

const helmet = require('helmet');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// Set CSP headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],  // No 'unsafe-inline'
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        }
    }
}));

// Sanitize user input before rendering
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const cleanHTML = DOMPurify.sanitize(userInput);
''',
        },
        'php': {
            'title': 'PHP XSS Prevention',
            'code': '''<?php
// Always use htmlspecialchars() when outputting user data
// BAD:
// echo $_GET['name'];

// GOOD:
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// For JSON contexts:
echo json_encode($user_data, JSON_HEX_TAG | JSON_HEX_AMP);

// Set CSP header:
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
?>
''',
        },
    },
    'SQLi': {
        'python_flask': {
            'title': 'Flask/SQLAlchemy Parameterized Queries',
            'code': '''# BAD - SQL Injection vulnerable:
# query = f"SELECT * FROM users WHERE name = '{user_input}'"
# db.execute(query)

# GOOD - Parameterized query with SQLAlchemy:
from sqlalchemy import text

# Option 1: SQLAlchemy ORM (recommended)
user = User.query.filter_by(username=user_input).first()

# Option 2: Raw SQL with parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE name = :username"),
    {"username": user_input}
)

# Option 3: SQLAlchemy Core
from sqlalchemy import select
stmt = select(users_table).where(users_table.c.name == user_input)
result = db.session.execute(stmt)
''',
        },
        'python_django': {
            'title': 'Django ORM Parameterized Queries',
            'code': '''# BAD - SQL Injection vulnerable:
# User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{input}'")

# GOOD - Django ORM (always parameterized):
user = User.objects.filter(username=user_input).first()

# If raw SQL is needed, use parameters:
users = User.objects.raw(
    "SELECT * FROM auth_user WHERE username = %s",
    [user_input]
)

# For complex queries:
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT * FROM auth_user WHERE username = %s AND active = %s",
        [user_input, True]
    )
''',
        },
        'javascript_express': {
            'title': 'Node.js Parameterized Queries',
            'code': '''// BAD - SQL Injection vulnerable:
// db.query(`SELECT * FROM users WHERE name = '${userInput}'`);

// GOOD - Parameterized queries:

// MySQL2:
const [rows] = await db.execute(
    'SELECT * FROM users WHERE name = ?',
    [userInput]
);

// PostgreSQL (pg):
const result = await pool.query(
    'SELECT * FROM users WHERE name = $1',
    [userInput]
);

// Sequelize ORM:
const user = await User.findOne({
    where: { username: userInput }
});

// Knex.js query builder:
const user = await knex('users').where('name', userInput).first();
''',
        },
        'php': {
            'title': 'PHP PDO Prepared Statements',
            'code': '''<?php
// BAD - SQL Injection vulnerable:
// $query = "SELECT * FROM users WHERE name = '$_GET[name]'";
// $result = mysqli_query($conn, $query);

// GOOD - PDO Prepared Statements:
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
$stmt->execute(['name' => $_GET['name']]);
$user = $stmt->fetch();

// MySQLi Prepared Statements:
$stmt = $mysqli->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $_GET['name']);
$stmt->execute();
$result = $stmt->get_result();
?>
''',
        },
    },
    'CSRF': {
        'python_flask': {
            'title': 'Flask CSRF Protection',
            'code': '''# Install: pip install flask-wtf
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# In templates, include CSRF token:
# <form method="POST">
#     <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#     ...
# </form>

# For AJAX requests:
# <meta name="csrf-token" content="{{ csrf_token() }}">
# In JavaScript:
# fetch('/api/data', {
#     method: 'POST',
#     headers: { 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content }
# });
''',
        },
        'python_django': {
            'title': 'Django CSRF Protection',
            'code': '''# Django has CSRF protection enabled by default via middleware.
# Ensure 'django.middleware.csrf.CsrfViewMiddleware' is in MIDDLEWARE.

# In templates:
# <form method="POST">
#     {% csrf_token %}
#     ...
# </form>

# For AJAX with fetch:
# const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
# fetch('/api/endpoint', {
#     method: 'POST',
#     headers: { 'X-CSRFToken': csrftoken },
#     body: JSON.stringify(data)
# });
''',
        },
        'javascript_express': {
            'title': 'Express.js CSRF Protection',
            'code': '''// Install: npm install csrf-csrf cookie-parser
const { doubleCsrf } = require("csrf-csrf");
const cookieParser = require("cookie-parser");

app.use(cookieParser());

const { generateToken, doubleCsrfProtection } = doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET,
    cookieName: "__csrf",
    cookieOptions: { sameSite: "strict", secure: true },
});

app.use(doubleCsrfProtection);

// Generate token for forms:
app.get('/form', (req, res) => {
    const token = generateToken(req, res);
    res.render('form', { csrfToken: token });
});
''',
        },
    },
    'SSRF': {
        'python_flask': {
            'title': 'Python SSRF Prevention',
            'code': '''import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}

def is_safe_url(url: str) -> bool:
    """Validate URL is not targeting internal resources."""
    try:
        parsed = urlparse(url)

        # Only allow http/https
        if parsed.scheme not in ('http', 'https'):
            return False

        # Check domain allowlist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False

        # Block internal IPs
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                return False
        except ValueError:
            pass  # Not an IP, it's a hostname

        return True
    except Exception:
        return False

# Usage:
# if is_safe_url(user_provided_url):
#     response = requests.get(user_provided_url)
''',
        },
    },
    'LFI': {
        'python_flask': {
            'title': 'Python Path Traversal Prevention',
            'code': '''import os
from pathlib import Path

ALLOWED_DIR = Path('/app/templates')
ALLOWED_FILES = {'about.html', 'contact.html', 'faq.html'}

def safe_file_read(filename: str) -> str:
    """Safely read a file preventing path traversal."""
    # Option 1: Allowlist approach (most secure)
    if filename not in ALLOWED_FILES:
        raise ValueError(f"File not allowed: {filename}")

    # Option 2: Path validation
    requested_path = (ALLOWED_DIR / filename).resolve()
    if not str(requested_path).startswith(str(ALLOWED_DIR.resolve())):
        raise ValueError("Path traversal detected")

    return requested_path.read_text()

# NEVER do this:
# open(f"/app/templates/{user_input}")
''',
        },
    },
    'RCE': {
        'python_flask': {
            'title': 'Python Command Injection Prevention',
            'code': '''import subprocess
import shlex

# NEVER use shell=True with user input:
# subprocess.run(f"ping {user_input}", shell=True)  # VULNERABLE

# GOOD - Use list arguments (no shell interpretation):
def safe_ping(host: str) -> str:
    # Validate input
    import re
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid hostname")

    result = subprocess.run(
        ['ping', '-c', '4', host],  # List args, no shell
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout

# Use language-native libraries instead of shell commands:
# Instead of: subprocess.run('curl http://example.com', shell=True)
# Use: requests.get('http://example.com')
''',
        },
    },
    'Open Redirect': {
        'python_flask': {
            'title': 'Python Open Redirect Prevention',
            'code': '''from urllib.parse import urlparse

ALLOWED_REDIRECT_DOMAINS = {'example.com', 'app.example.com'}

def safe_redirect(url: str) -> str:
    """Validate redirect URL to prevent open redirect."""
    # Option 1: Only allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return url

    # Option 2: Allowlist domains
    try:
        parsed = urlparse(url)
        if parsed.netloc in ALLOWED_REDIRECT_DOMAINS:
            return url
    except Exception:
        pass

    # Default: redirect to home
    return '/'

# Usage in Flask:
# @app.route('/login')
# def login():
#     next_url = safe_redirect(request.args.get('next', '/'))
#     return redirect(next_url)
''',
        },
    },
    'Security Headers': {
        'python_flask': {
            'title': 'Flask Security Headers',
            'code': '''# Install: pip install flask-talisman
from flask_talisman import Talisman

csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data:",
}

Talisman(app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_httponly=True,
    session_cookie_samesite='Lax',
)

# Or manually:
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
''',
        },
        'javascript_express': {
            'title': 'Express.js Security Headers (Helmet)',
            'code': '''// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet());  // Enables all default security headers

// Or configure individually:
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
''',
        },
    },
}


class RemediationGenerator:
    """
    Generates language/framework-specific remediation code for each finding.

    This is a unique feature — scanners typically only describe what's wrong.
    This engine provides copy-paste-ready fix code.
    """

    def __init__(self):
        logger.info("Remediation Generator initialized")

    def get_remediation(self, finding: Finding, framework: str = 'python_flask') -> Dict:
        """
        Get remediation code for a specific finding.

        Args:
            finding: The vulnerability finding
            framework: Target framework (python_flask, python_django,
                      javascript_express, php)

        Returns:
            Dict with 'title', 'code', and 'available_frameworks'
        """
        vuln_type = finding.vuln_type
        templates = REMEDIATION_TEMPLATES.get(vuln_type, {})

        available = list(templates.keys())

        if framework in templates:
            return {
                **templates[framework],
                'available_frameworks': available,
            }
        elif available:
            # Fall back to first available
            first = available[0]
            return {
                **templates[first],
                'available_frameworks': available,
            }
        else:
            return {
                'title': f'{vuln_type} Remediation',
                'code': finding.remediation or f'No specific code template available for {vuln_type}.',
                'available_frameworks': [],
            }

    def enrich_findings(self, findings: List[Finding], framework: str = 'python_flask') -> List[Finding]:
        """
        Enrich findings with detailed remediation code.

        Args:
            findings: List of findings to enrich
            framework: Target framework for code samples

        Returns:
            The same findings list with enriched remediation fields
        """
        for finding in findings:
            remediation_info = self.get_remediation(finding, framework)
            if remediation_info.get('code'):
                finding.remediation = (
                    f"{finding.remediation}\n\n"
                    f"--- {remediation_info['title']} ---\n"
                    f"{remediation_info['code']}"
                ).strip()

        logger.info(f"Enriched {len(findings)} findings with remediation code")
        return findings
