"""
Open Redirect vulnerability scanner.

Detects unvalidated redirects by injecting external URLs into redirect-like
parameters and checking if the response performs a redirect to the injected URL.
"""

from typing import List, Optional
from urllib.parse import urlparse
from pathlib import Path

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    PAYLOAD_DIR,
    REDIRECT_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Built-in redirect payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F%2F",
    "https://evil.com%00",
    "https://evil.com?.example.com",
    "https://example.com@evil.com",
    "https://evil.com#.example.com",
    "https://evil.com\\@example.com",
    "/redirect?url=https://evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "\\\\evil.com",
    "https:evil.com",
    "https:/evil.com",
    "\t//evil.com",
    " //evil.com",
]

# Parameters that commonly accept redirect URLs
REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_url', 'redirect_uri',
    'return', 'return_url', 'returnurl', 'return_to',
    'next', 'next_url', 'goto', 'go', 'target',
    'dest', 'destination', 'rurl', 'redirect_to',
    'continue', 'callback', 'forward', 'forward_url',
    'out', 'view', 'login_url', 'logout', 'checkout_url',
    'image_url', 'redir', 'ref', 'referrer',
]


class RedirectScanner(BaseScanner):
    """
    Open Redirect scanner that tests redirect-like parameters.

    Checks both form fields and URL query parameters for unvalidated
    redirects. Uses redirect detection via response status codes and
    Location headers.
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"Open Redirect Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "Open Redirect"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load redirect payloads."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / REDIRECT_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file)
        if not payloads:
            payloads = REDIRECT_PAYLOADS

        return payloads

    def _is_redirect_parameter(self, field_name: str) -> bool:
        """Check if field name suggests it handles redirects."""
        return field_name.lower() in REDIRECT_PARAMS or any(
            p in field_name.lower() for p in ['redirect', 'return', 'next', 'goto', 'url', 'dest']
        )

    def _check_redirect(self, response, payload: str) -> Optional[str]:
        """
        Check if response redirects to our injected URL.

        Args:
            response: HTTP response object
            payload: The injected redirect URL

        Returns:
            Evidence string if redirect detected, None otherwise
        """
        # Check Location header
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get('Location', '')
            if self._is_external_redirect(location, payload):
                return f"Redirect to: {location}"

        # Check redirect chain (if redirects were followed)
        if response.history:
            for resp in response.history:
                location = resp.headers.get('Location', '')
                if self._is_external_redirect(location, payload):
                    return f"Redirect chain includes external URL: {location}"

        # Check meta refresh tags
        if '<meta' in response.text.lower() and 'refresh' in response.text.lower():
            if 'evil.com' in response.text.lower():
                return "Meta refresh redirect to external URL detected"

        # Check JavaScript redirects
        js_redirect_patterns = [
            'window.location', 'document.location', 'location.href',
            'location.replace', 'location.assign'
        ]
        for pattern in js_redirect_patterns:
            if pattern in response.text and 'evil.com' in response.text:
                return f"JavaScript redirect via {pattern} to external URL"

        return None

    def _is_external_redirect(self, location: str, payload: str) -> bool:
        """Check if a Location header points to an external domain."""
        try:
            parsed = urlparse(location)
            if parsed.netloc and 'evil.com' in parsed.netloc:
                return True
            # Check for protocol-relative URLs
            if location.startswith('//') and 'evil.com' in location:
                return True
        except Exception:
            pass

        # Check for payload fragments in the location
        if payload.replace('https://', '').replace('http://', '') in location:
            return True

        return False

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan form for open redirect vulnerabilities."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for Open Redirect")

        # Focus on redirect-like parameters
        redirect_fields = [
            f for f in form.fields
            if f.name and self._is_redirect_parameter(f.name)
        ]

        # Also test other visible fields with fewer payloads
        other_fields = [
            f for f in self._get_testable_fields(form)
            if f.name and not self._is_redirect_parameter(f.name)
        ]

        fields_to_test = [(f, self.payloads) for f in redirect_fields]
        fields_to_test += [(f, self.payloads[:3]) for f in other_fields]

        for field, payloads in fields_to_test:
            field_vulnerable = False

            for payload in payloads:
                if field_vulnerable:
                    break

                form_data = self._build_form_data(form, field.name, payload)

                try:
                    # Don't follow redirects so we can inspect the Location header
                    if form.method == 'POST':
                        response = self.http_client.session.post(
                            form.action, data=form_data,
                            timeout=self.http_client.timeout,
                            allow_redirects=False
                        )
                    else:
                        response = self.http_client.session.get(
                            form.action, params=form_data,
                            timeout=self.http_client.timeout,
                            allow_redirects=False
                        )

                    evidence = self._check_redirect(response, payload)
                    if evidence:
                        finding = Finding(
                            vuln_type='Open Redirect',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity='MEDIUM',
                            method=form.method,
                            description=f'Open redirect via {field.name} parameter',
                            remediation='Validate redirect URLs against an allowlist of permitted domains. '
                                        'Use relative URLs instead of absolute URLs for internal redirects. '
                                        'Never use user input directly in redirect targets.',
                            cwe_id=CWE_MAPPINGS.get('Open Redirect', ''),
                            owasp_category=OWASP_MAPPINGS.get('Open Redirect', ''),
                            confidence='HIGH',
                            scanner_module='RedirectScanner',
                            tags=['open-redirect'],
                        )
                        findings.append(finding)
                        logger.warning(f"Open redirect in {form.action} param '{field.name}'")
                        field_vulnerable = True

                except Exception as e:
                    logger.error(f"Error testing redirect on {form.action}: {e}")

        return findings
