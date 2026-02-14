"""
Server-Side Request Forgery (SSRF) vulnerability scanner.

Detects SSRF by injecting URLs pointing to internal/reserved IP ranges
and cloud metadata endpoints, then checking for indicators of successful
internal resource access in responses.
"""

from typing import List, Optional
from pathlib import Path

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    PAYLOAD_DIR,
    SSRF_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Built-in SSRF payloads targeting internal resources
SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:22",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0x7f000001",
    "http://2130706433",
    # Internal networks
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://172.16.0.1",
    # Cloud metadata endpoints
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    # URL schema tricks
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:11211/info",
    "gopher://127.0.0.1:25/",
    # Bypass techniques
    "http://127.1",
    "http://0177.0.0.1",
    "http://127.0.0.1.nip.io",
    "http://spoofed.burpcollaborator.net",
]

# Indicators that SSRF was successful
SSRF_INDICATORS = [
    # Linux file contents
    "root:x:0:0",
    "/bin/bash",
    "/bin/sh",
    # Windows file contents
    "[fonts]",
    "[extensions]",
    # AWS metadata
    "ami-id",
    "instance-id",
    "instance-type",
    "security-credentials",
    # Azure metadata
    "vmId",
    "subscriptionId",
    # GCP metadata
    "computeMetadata",
    # Generic internal service responses
    "Apache/",
    "nginx/",
    "Server:",
    "X-Powered-By:",
    # Error messages indicating connection attempt
    "Connection refused",
    "Connection timed out",
    "No route to host",
]


class SSRFScanner(BaseScanner):
    """
    SSRF scanner that tests URL-accepting parameters.

    Focuses on form fields that typically accept URLs (name contains
    url, link, redirect, path, file, etc.) and injects internal
    resource URLs to detect server-side request forgery.
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"SSRF Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "SSRF"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load SSRF payloads."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / SSRF_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file)
        if not payloads:
            payloads = SSRF_PAYLOADS

        return payloads

    def _is_url_parameter(self, field_name: str) -> bool:
        """Check if a field name suggests it accepts URL input."""
        url_indicators = [
            'url', 'uri', 'link', 'href', 'src', 'source',
            'redirect', 'return', 'next', 'goto', 'dest',
            'destination', 'path', 'file', 'page', 'load',
            'fetch', 'request', 'callback', 'endpoint',
            'target', 'feed', 'host', 'site', 'domain',
            'image', 'img', 'pic', 'photo', 'avatar',
        ]
        name_lower = field_name.lower()
        return any(indicator in name_lower for indicator in url_indicators)

    def _check_ssrf_indicators(self, response_text: str, payload: str) -> Optional[str]:
        """Check if response indicates successful SSRF."""
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in response_text.lower():
                # Extract evidence around the indicator
                pos = response_text.lower().find(indicator.lower())
                start = max(0, pos - 30)
                end = min(len(response_text), pos + len(indicator) + 30)
                return response_text[start:end].strip()[:200]
        return None

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan form for SSRF vulnerabilities."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for SSRF")

        # Test ALL fields, but prioritize URL-like field names
        all_fields = list(form.fields)
        url_fields = [f for f in all_fields if f.name and self._is_url_parameter(f.name)]
        other_fields = [f for f in self._get_testable_fields(form)
                        if f.name and not self._is_url_parameter(f.name)]

        # Test URL fields first, then other fields with fewer payloads
        fields_to_test = [(f, self.payloads) for f in url_fields]
        fields_to_test += [(f, self.payloads[:5]) for f in other_fields]

        for field, payloads in fields_to_test:
            field_vulnerable = False

            for payload in payloads:
                if field_vulnerable:
                    break

                form_data = self._build_form_data(form, field.name, payload)

                try:
                    response = self._submit_form(form, form_data)
                    if not response:
                        continue

                    evidence = self._check_ssrf_indicators(response.text, payload)
                    if evidence:
                        finding = Finding(
                            vuln_type='SSRF',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity='CRITICAL' if '169.254.169.254' in payload else 'HIGH',
                            method=form.method,
                            description=f'Server-Side Request Forgery via {field.name}',
                            remediation='Validate and sanitize all URLs. Use allowlists for permitted '
                                        'domains/IPs. Block requests to internal/private IP ranges. '
                                        'Disable unnecessary URL schemes (file://, gopher://, etc.).',
                            cwe_id=CWE_MAPPINGS.get('SSRF', ''),
                            owasp_category=OWASP_MAPPINGS.get('SSRF', ''),
                            confidence='MEDIUM',
                            scanner_module='SSRFScanner',
                            tags=['ssrf'],
                        )
                        findings.append(finding)
                        logger.warning(f"SSRF found in {form.action} param '{field.name}'")
                        field_vulnerable = True

                except Exception as e:
                    logger.error(f"Error testing SSRF on {form.action}: {e}")

        return findings
