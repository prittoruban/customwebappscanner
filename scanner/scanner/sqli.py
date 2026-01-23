"""
SQL Injection (SQLi) vulnerability scanner.

Detects SQL injection vulnerabilities using:
1. Boolean-based blind SQLi (true/false conditions)
2. Error-based SQLi (SQL error messages in response)
3. Time-based blind SQLi (response delay detection)
"""

import time
import re
from typing import List, Optional
from pathlib import Path

from crawler.crawler import Form
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    SQLI_ERROR_PATTERNS,
    SQLI_TIME_THRESHOLD,
    MAX_PAYLOADS_PER_INPUT,
    PAYLOAD_DIR,
    SQLI_PAYLOAD_FILE
)
from scanner.xss import Finding  # Reuse Finding dataclass

logger = get_logger(__name__)


class SQLiScanner:
    """
    SQL Injection vulnerability scanner.
    
    Testing methodology:
    1. Error-based: Inject SQL syntax errors and check for database errors
    2. Boolean-based: Compare responses with true/false conditions
    3. Time-based: Inject sleep/delay functions and measure response time
    """
    
    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        """
        Initialize SQLi scanner.
        
        Args:
            http_client: HTTP client for making requests
            payload_file: Path to SQLi payload file (uses default if None)
        """
        self.http_client = http_client
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"SQLi Scanner initialized with {len(self.payloads)} payloads")
    
    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """
        Load SQLi payloads from file.
        
        Args:
            payload_file: Path to payload file
            
        Returns:
            List of payload strings
        """
        if payload_file is None:
            payload_file = PAYLOAD_DIR / SQLI_PAYLOAD_FILE
        
        payloads = []
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}. Using default payloads.")
            # Default SQLi payloads if file not found
            payloads = [
                # Error-based
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                # Boolean-based
                "' AND '1'='1",
                "' AND '1'='2",
                # Time-based
                "' OR SLEEP(5) --",
                "'; WAITFOR DELAY '0:0:5' --",
                "' OR pg_sleep(5) --",
            ]
        
        return payloads[:MAX_PAYLOADS_PER_INPUT]
    
    def _check_sql_errors(self, response_text: str) -> Optional[str]:
        """
        Check if response contains SQL error messages.
        
        Args:
            response_text: HTTP response body
            
        Returns:
            Error pattern that matched, or None if no errors found
        """
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        return None
    
    def _extract_error_evidence(self, response_text: str, error_pattern: str, max_length: int = 300) -> str:
        """
        Extract SQL error message from response for evidence.
        
        Args:
            response_text: Response body
            error_pattern: The error pattern that was matched
            max_length: Maximum evidence length
            
        Returns:
            Evidence snippet
        """
        try:
            # Find the error in response
            match = re.search(error_pattern, response_text, re.IGNORECASE)
            if match:
                pos = match.start()
                # Extract context around the error
                start = max(0, pos - 50)
                end = min(len(response_text), pos + 200)
                snippet = response_text[start:end]
                return snippet.strip()[:max_length]
        except Exception as e:
            logger.debug(f"Failed to extract SQL error evidence: {e}")
        
        return f"SQL error pattern detected: {error_pattern}"
    
    def _test_time_based(self, form: Form, field_name: str, payload: str) -> bool:
        """
        Test for time-based blind SQLi by measuring response time.
        
        Args:
            form: Form to test
            field_name: Field to inject payload into
            payload: Time-based SQLi payload
            
        Returns:
            True if significant delay detected (indicating vulnerability)
        """
        # Build form data with time-based payload
        form_data = {}
        for f in form.fields:
            if f.name == field_name:
                form_data[f.name] = payload
            else:
                form_data[f.name] = f.value if f.value else 'test'
        
        # Measure response time
        start_time = time.time()
        
        try:
            if form.method == 'POST':
                response = self.http_client.post(form.action, data=form_data)
            else:
                response = self.http_client.get(form.action, params=form_data)
            
            elapsed = time.time() - start_time
            
            # If response took significantly longer, likely vulnerable
            if elapsed >= SQLI_TIME_THRESHOLD:
                logger.warning(f"Time-based SQLi detected: {elapsed:.2f}s delay")
                return True
        
        except Exception as e:
            logger.error(f"Error in time-based SQLi test: {e}")
        
        return False
    
    def scan_form(self, form: Form) -> List[Finding]:
        """
        Scan a single form for SQL injection vulnerabilities.
        
        Tests each input field with SQLi payloads using multiple techniques.
        
        Args:
            form: Form object to test
            
        Returns:
            List of Finding objects for discovered vulnerabilities
        """
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for SQLi")
        
        # Get testable fields
        testable_fields = [
            f for f in form.fields
            if f.field_type not in ['hidden', 'submit', 'button', 'reset']
        ]
        
        if not testable_fields:
            logger.debug(f"No testable fields in form {form.action}")
            return findings
        
        # Test each field
        for field in testable_fields:
            field_vulnerable = False
            
            for payload in self.payloads:
                # Skip if we already found a vulnerability in this field
                if field_vulnerable:
                    break
                
                # Build form data
                form_data = {}
                for f in form.fields:
                    if f.name == field.name:
                        form_data[f.name] = payload
                    else:
                        form_data[f.name] = f.value if f.value else 'test'
                
                try:
                    # Submit form
                    if form.method == 'POST':
                        response = self.http_client.post(form.action, data=form_data)
                    else:
                        response = self.http_client.get(form.action, params=form_data)
                    
                    if not response:
                        continue
                    
                    # Check for error-based SQLi
                    error_pattern = self._check_sql_errors(response.text)
                    if error_pattern:
                        evidence = self._extract_error_evidence(response.text, error_pattern)
                        
                        finding = Finding(
                            vuln_type='SQLi',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity='CRITICAL',
                            method=form.method,
                            description=f'Error-based SQL Injection in {field.name} parameter'
                        )
                        findings.append(finding)
                        logger.warning(f"SQLi found in {form.action} parameter '{field.name}' (error-based)")
                        field_vulnerable = True
                        continue
                    
                    # Check for time-based SQLi (only for specific payloads)
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload.lower():
                        if self._test_time_based(form, field.name, payload):
                            finding = Finding(
                                vuln_type='SQLi',
                                url=form.action,
                                parameter=field.name,
                                payload=payload,
                                evidence=f'Response delayed by {SQLI_TIME_THRESHOLD}+ seconds',
                                severity='HIGH',
                                method=form.method,
                                description=f'Time-based SQL Injection in {field.name} parameter'
                            )
                            findings.append(finding)
                            logger.warning(f"SQLi found in {form.action} parameter '{field.name}' (time-based)")
                            field_vulnerable = True
                
                except Exception as e:
                    logger.error(f"Error testing SQLi on {form.action}: {e}")
        
        return findings
    
    def scan(self, forms: List[Form]) -> List[Finding]:
        """
        Scan multiple forms for SQL injection vulnerabilities.
        
        Args:
            forms: List of Form objects to scan
            
        Returns:
            List of all SQLi findings
        """
        all_findings = []
        
        for form in forms:
            findings = self.scan_form(form)
            all_findings.extend(findings)
        
        logger.info(f"SQLi scan complete. Found {len(all_findings)} vulnerabilities")
        return all_findings
