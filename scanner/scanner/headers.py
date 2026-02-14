"""
Security Headers and Cookie analyzer.

Checks HTTP response headers for security-critical headers and analyzes
cookie security flags. This is a passive scanner that doesn't require forms.
"""

from typing import List, Dict, Optional
import re

from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    SECURITY_HEADERS,
    COOKIE_SECURITY_FLAGS,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Dangerous header values
DANGEROUS_CSP_DIRECTIVES = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "*",
]

CORS_DANGEROUS_ORIGINS = [
    "*",
    "null",
]


class HeadersScanner:
    """
    Passive security headers and cookie analyzer.

    Checks for:
    1. Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
    2. Misconfigured security headers (weak CSP, permissive CORS)
    3. Cookie security flags (Secure, HttpOnly, SameSite)
    4. Information disclosure headers (Server, X-Powered-By)
    """

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        logger.info("Security Headers Scanner initialized")

    def scan_url(self, url: str) -> List[Finding]:
        """
        Scan a URL for security header issues.

        Args:
            url: URL to analyze

        Returns:
            List of Finding objects
        """
        findings = []
        logger.info(f"Scanning headers for {url}")

        response = self.http_client.get(url)
        if not response:
            logger.warning(f"Failed to fetch {url} for header analysis")
            return findings

        headers = response.headers

        # Check missing security headers
        findings.extend(self._check_missing_headers(url, headers))

        # Check CSP configuration
        findings.extend(self._check_csp(url, headers))

        # Check CORS configuration
        findings.extend(self._check_cors(url, headers))

        # Check information disclosure
        findings.extend(self._check_info_disclosure(url, headers))

        # Check cookie security
        findings.extend(self._check_cookies(url, response))

        return findings

    def _check_missing_headers(self, url: str, headers: dict) -> List[Finding]:
        """Check for missing security headers."""
        findings = []

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers.keys()}:
                finding = Finding(
                    vuln_type='Security Headers',
                    url=url,
                    parameter=header_name,
                    payload='N/A',
                    evidence=f'Missing header: {header_name}',
                    severity=info['severity'],
                    method='GET',
                    description=info['description'],
                    remediation=info['remediation'],
                    cwe_id=CWE_MAPPINGS.get('Security Headers', ''),
                    owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                    confidence='HIGH',
                    scanner_module='HeadersScanner',
                    tags=['headers', 'missing-header', header_name.lower()],
                )
                findings.append(finding)

        return findings

    def _check_csp(self, url: str, headers: dict) -> List[Finding]:
        """Analyze Content-Security-Policy for weaknesses."""
        findings = []

        csp = None
        for k, v in headers.items():
            if k.lower() == 'content-security-policy':
                csp = v
                break

        if not csp:
            return findings  # Missing CSP is caught by _check_missing_headers

        for directive in DANGEROUS_CSP_DIRECTIVES:
            if directive in csp.lower():
                finding = Finding(
                    vuln_type='Security Headers',
                    url=url,
                    parameter='Content-Security-Policy',
                    payload='N/A',
                    evidence=f'CSP contains dangerous directive: {directive}. Full CSP: {csp[:200]}',
                    severity='MEDIUM',
                    method='GET',
                    description=f'Content-Security-Policy contains {directive} which weakens XSS protection',
                    remediation=f'Remove {directive} from CSP. Use nonces or hashes for inline scripts.',
                    cwe_id=CWE_MAPPINGS.get('Security Headers', ''),
                    owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                    confidence='HIGH',
                    scanner_module='HeadersScanner',
                    tags=['headers', 'weak-csp'],
                )
                findings.append(finding)

        return findings

    def _check_cors(self, url: str, headers: dict) -> List[Finding]:
        """Check for overly permissive CORS configuration."""
        findings = []

        acao = None
        for k, v in headers.items():
            if k.lower() == 'access-control-allow-origin':
                acao = v
                break

        if acao and acao.strip() in CORS_DANGEROUS_ORIGINS:
            finding = Finding(
                vuln_type='Security Headers',
                url=url,
                parameter='Access-Control-Allow-Origin',
                payload='N/A',
                evidence=f'CORS allows dangerous origin: {acao}',
                severity='HIGH',
                method='GET',
                description='Overly permissive CORS policy allows any origin to access resources',
                remediation='Restrict Access-Control-Allow-Origin to specific trusted domains.',
                cwe_id='CWE-942',
                owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                confidence='HIGH',
                scanner_module='HeadersScanner',
                tags=['headers', 'cors', 'misconfiguration'],
            )
            findings.append(finding)

        return findings

    def _check_info_disclosure(self, url: str, headers: dict) -> List[Finding]:
        """Check for information disclosure in response headers."""
        findings = []

        disclosure_headers = {
            'Server': 'Server header discloses web server technology',
            'X-Powered-By': 'X-Powered-By header discloses application framework',
            'X-AspNet-Version': 'X-AspNet-Version discloses .NET framework version',
            'X-AspNetMvc-Version': 'X-AspNetMvc-Version discloses ASP.NET MVC version',
        }

        for header_name, description in disclosure_headers.items():
            for k, v in headers.items():
                if k.lower() == header_name.lower():
                    finding = Finding(
                        vuln_type='Security Headers',
                        url=url,
                        parameter=header_name,
                        payload='N/A',
                        evidence=f'{header_name}: {v}',
                        severity='LOW',
                        method='GET',
                        description=description,
                        remediation=f'Remove or suppress the {header_name} header in production.',
                        cwe_id='CWE-200',
                        owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                        confidence='HIGH',
                        scanner_module='HeadersScanner',
                        tags=['headers', 'info-disclosure'],
                    )
                    findings.append(finding)
                    break

        return findings

    def _check_cookies(self, url: str, response) -> List[Finding]:
        """Analyze cookies for missing security flags."""
        findings = []

        for cookie in response.cookies:
            cookie_str = str(response.headers.get('Set-Cookie', ''))

            # Check Secure flag
            if not cookie.secure and url.startswith('https://'):
                findings.append(Finding(
                    vuln_type='Security Headers',
                    url=url,
                    parameter=f'Cookie: {cookie.name}',
                    payload='N/A',
                    evidence=f'Cookie "{cookie.name}" missing Secure flag',
                    severity='MEDIUM',
                    method='GET',
                    description=COOKIE_SECURITY_FLAGS['secure'],
                    remediation='Set the Secure flag on all cookies to prevent transmission over HTTP.',
                    cwe_id='CWE-614',
                    owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                    confidence='HIGH',
                    scanner_module='HeadersScanner',
                    tags=['cookies', 'missing-secure'],
                ))

            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('httponly') and not cookie.has_nonstandard_attr('HttpOnly'):
                # requests library doesn't directly expose httponly, check from header
                if 'httponly' not in cookie_str.lower():
                    findings.append(Finding(
                        vuln_type='Security Headers',
                        url=url,
                        parameter=f'Cookie: {cookie.name}',
                        payload='N/A',
                        evidence=f'Cookie "{cookie.name}" missing HttpOnly flag',
                        severity='MEDIUM',
                        method='GET',
                        description=COOKIE_SECURITY_FLAGS['httponly'],
                        remediation='Set HttpOnly flag on session cookies to prevent JavaScript access.',
                        cwe_id='CWE-1004',
                        owasp_category=OWASP_MAPPINGS.get('Security Headers', ''),
                        confidence='HIGH',
                        scanner_module='HeadersScanner',
                        tags=['cookies', 'missing-httponly'],
                    ))

            # Check SameSite attribute
            if 'samesite' not in cookie_str.lower():
                findings.append(Finding(
                    vuln_type='Security Headers',
                    url=url,
                    parameter=f'Cookie: {cookie.name}',
                    payload='N/A',
                    evidence=f'Cookie "{cookie.name}" missing SameSite attribute',
                    severity='LOW',
                    method='GET',
                    description=COOKIE_SECURITY_FLAGS['samesite'],
                    remediation='Set SameSite=Lax or SameSite=Strict on cookies.',
                    cwe_id=CWE_MAPPINGS.get('CSRF', ''),
                    owasp_category=OWASP_MAPPINGS.get('CSRF', ''),
                    confidence='HIGH',
                    scanner_module='HeadersScanner',
                    tags=['cookies', 'missing-samesite'],
                ))

        return findings
