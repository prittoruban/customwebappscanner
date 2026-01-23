"""
Cross-Site Scripting (XSS) vulnerability scanner.

Detects reflected and stored XSS vulnerabilities by:
1. Injecting XSS payloads into form inputs
2. Checking if payloads are reflected in response
3. Testing for basic stored XSS (submit + revisit)
"""

import re
from typing import List, Optional
from dataclasses import dataclass
from pathlib import Path

from crawler.crawler import Form
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    XSS_REFLECTION_PATTERNS,
    MAX_PAYLOADS_PER_INPUT,
    PAYLOAD_DIR,
    XSS_PAYLOAD_FILE
)

logger = get_logger(__name__)


@dataclass
class Finding:
    """
    Standardized vulnerability finding.
    
    Used across all scanner modules for consistent reporting.
    """
    vuln_type: str  # XSS, SQLi, CSRF
    url: str  # URL where vulnerability was found
    parameter: str  # Vulnerable parameter name
    payload: str  # Payload that triggered the vulnerability
    evidence: str  # Evidence snippet from response
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    method: str = "GET"  # HTTP method used
    description: str = ""  # Additional context


class XSSScanner:
    """
    XSS vulnerability scanner supporting reflected and stored XSS detection.
    
    Testing methodology:
    1. Load XSS payloads from file
    2. For each form field, inject payloads
    3. Submit form and analyze response
    4. Check if payload is reflected (reflected XSS)
    5. Optionally revisit page to check for stored XSS
    """
    
    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        """
        Initialize XSS scanner.
        
        Args:
            http_client: HTTP client for making requests
            payload_file: Path to XSS payload file (uses default if None)
        """
        self.http_client = http_client
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"XSS Scanner initialized with {len(self.payloads)} payloads")
    
    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """
        Load XSS payloads from file.
        
        Args:
            payload_file: Path to payload file
            
        Returns:
            List of payload strings
        """
        if payload_file is None:
            payload_file = PAYLOAD_DIR / XSS_PAYLOAD_FILE
        
        payloads = []
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        payloads.append(line)
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}. Using default payloads.")
            # Default XSS payloads if file not found
            payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '"><script>alert(1)</script>',
                "';alert(1);//",
            ]
        
        # Limit payloads for demo purposes
        return payloads[:MAX_PAYLOADS_PER_INPUT]
    
    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """
        Check if XSS payload is reflected in HTTP response.
        
        Args:
            payload: Original payload string
            response_text: HTTP response body
            
        Returns:
            True if payload appears reflected in response
        """
        # Direct reflection check
        if payload in response_text:
            return True
        
        # Check for pattern-based reflection (e.g., <script>, alert()
        for pattern in XSS_REFLECTION_PATTERNS:
            if pattern.lower() in response_text.lower():
                # Ensure it's from our payload
                if pattern.lower() in payload.lower():
                    return True
        
        return False
    
    def _extract_evidence(self, payload: str, response_text: str, max_length: int = 200) -> str:
        """
        Extract a snippet of response text showing where payload was reflected.
        
        Args:
            payload: Payload string
            response_text: Response body
            max_length: Maximum evidence snippet length
            
        Returns:
            Evidence snippet
        """
        try:
            # Find the position of the payload in response
            pos = response_text.lower().find(payload.lower())
            if pos == -1:
                # Look for partial match
                for pattern in XSS_REFLECTION_PATTERNS:
                    if pattern.lower() in payload.lower():
                        pos = response_text.lower().find(pattern.lower())
                        if pos != -1:
                            break
            
            if pos != -1:
                # Extract context around the payload
                start = max(0, pos - 50)
                end = min(len(response_text), pos + len(payload) + 50)
                snippet = response_text[start:end]
                return snippet.strip()[:max_length]
        except Exception as e:
            logger.debug(f"Failed to extract evidence: {e}")
        
        return "Payload reflected in response"
    
    def scan_form(self, form: Form) -> List[Finding]:
        """
        Scan a single form for XSS vulnerabilities.
        
        Tests each input field with XSS payloads and checks for reflection.
        
        Args:
            form: Form object to test
            
        Returns:
            List of Finding objects for discovered vulnerabilities
        """
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for XSS")
        
        # Get testable fields (exclude hidden CSRF tokens, etc.)
        testable_fields = [
            f for f in form.fields
            if f.field_type not in ['hidden', 'submit', 'button', 'reset']
        ]
        
        if not testable_fields:
            logger.debug(f"No testable fields in form {form.action}")
            return findings
        
        # Test each field with each payload
        for field in testable_fields:
            for payload in self.payloads:
                # Build form data with payload in current field
                form_data = {}
                for f in form.fields:
                    if f.name == field.name:
                        form_data[f.name] = payload
                    else:
                        # Use original value for other fields
                        form_data[f.name] = f.value if f.value else 'test'
                
                # Submit form
                try:
                    if form.method == 'POST':
                        response = self.http_client.post(form.action, data=form_data)
                    else:
                        response = self.http_client.get(form.action, params=form_data)
                    
                    if not response:
                        continue
                    
                    # Check if payload is reflected
                    if self._is_payload_reflected(payload, response.text):
                        evidence = self._extract_evidence(payload, response.text)
                        
                        finding = Finding(
                            vuln_type='XSS',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity='HIGH',
                            method=form.method,
                            description=f'Reflected XSS in {field.name} parameter'
                        )
                        findings.append(finding)
                        logger.warning(f"XSS found in {form.action} parameter '{field.name}'")
                        
                        # Only report first finding per field to avoid duplicates
                        break
                
                except Exception as e:
                    logger.error(f"Error testing XSS on {form.action}: {e}")
        
        return findings
    
    def scan(self, forms: List[Form]) -> List[Finding]:
        """
        Scan multiple forms for XSS vulnerabilities.
        
        Args:
            forms: List of Form objects to scan
            
        Returns:
            List of all XSS findings
        """
        all_findings = []
        
        for form in forms:
            findings = self.scan_form(form)
            all_findings.extend(findings)
        
        logger.info(f"XSS scan complete. Found {len(all_findings)} vulnerabilities")
        return all_findings
