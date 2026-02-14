"""
Abstract base class for all vulnerability scanners.

Provides a consistent interface and shared functionality for scanner modules.
All scanner implementations must inherit from BaseScanner.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """
    Abstract base scanner that defines the interface for all vulnerability scanners.

    Subclasses must implement:
    - scan_form(form) -> List[Finding]
    - scanner_name (property)
    """

    def __init__(self, http_client: HTTPClient):
        """
        Initialize the base scanner.

        Args:
            http_client: HTTP client for making requests
        """
        self.http_client = http_client
        self._findings_count = 0

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return the human-readable name of this scanner."""
        ...

    @abstractmethod
    def scan_form(self, form: Form) -> List[Finding]:
        """
        Scan a single form for vulnerabilities.

        Args:
            form: Form object to test

        Returns:
            List of Finding objects for discovered vulnerabilities
        """
        ...

    def scan(self, forms: List[Form]) -> List[Finding]:
        """
        Scan multiple forms for vulnerabilities.

        Args:
            forms: List of Form objects to scan

        Returns:
            List of all findings
        """
        all_findings = []

        for form in forms:
            try:
                findings = self.scan_form(form)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"[{self.scanner_name}] Error scanning {form.action}: {e}")

        self._findings_count = len(all_findings)
        logger.info(f"{self.scanner_name} scan complete. Found {self._findings_count} vulnerabilities")
        return all_findings

    def _load_payloads_from_file(self, payload_file: Path, max_payloads: int = 200) -> List[str]:
        """
        Load payloads from a text file, skipping comments and blank lines.

        Args:
            payload_file: Path to the payload file
            max_payloads: Max number of payloads to load

        Returns:
            List of payload strings
        """
        payloads = []
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            return []

        return payloads[:max_payloads]

    def _get_testable_fields(self, form: Form) -> list:
        """
        Get form fields that are suitable for injection testing.

        Excludes hidden, submit, button, and reset fields.

        Args:
            form: Form to extract fields from

        Returns:
            List of testable FormField objects
        """
        return [
            f for f in form.fields
            if f.field_type not in ['hidden', 'submit', 'button', 'reset']
        ]

    def _build_form_data(self, form: Form, target_field: str, payload: str) -> dict:
        """
        Build form submission data, injecting payload into the target field.

        Args:
            form: Form containing fields
            target_field: Name of field to inject payload into
            payload: Payload string to inject

        Returns:
            Dictionary of field name -> value
        """
        form_data = {}
        for f in form.fields:
            if f.name == target_field:
                form_data[f.name] = payload
            else:
                form_data[f.name] = f.value if f.value else 'test'
        return form_data

    def _submit_form(self, form: Form, form_data: dict):
        """
        Submit form data using the appropriate HTTP method.

        Args:
            form: Form object with action and method
            form_data: Key-value data to submit

        Returns:
            Response object or None
        """
        if form.method == 'POST':
            return self.http_client.post(form.action, data=form_data)
        else:
            return self.http_client.get(form.action, params=form_data)
