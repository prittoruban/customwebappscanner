"""
SQL Injection (SQLi) vulnerability scanner with differential response analysis.

Production features:
1. Error-based detection with regex patterns for 10+ database engines
2. Differential response analysis for boolean-blind SQLi
3. Time-based detection with baseline measurement to avoid false positives
4. Response similarity scoring to detect subtle differences
5. Database engine fingerprinting from error messages
"""

import time
import re
from typing import List, Optional, Tuple
from pathlib import Path
from difflib import SequenceMatcher

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    SQLI_ERROR_PATTERNS,
    SQLI_TIME_THRESHOLD,
    SQLI_BASELINE_SAMPLES,
    MAX_PAYLOADS_PER_INPUT,
    PAYLOAD_DIR,
    SQLI_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Boolean-blind SQLi pairs: (true_condition, false_condition)
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1 --", "' OR 1=2 --"),
    ('" OR "1"="1', '" OR "1"="2'),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("1) OR (1=1", "1) OR (1=2"),
]

# Time-based payloads with expected delays
TIME_PAYLOADS = [
    ("' OR SLEEP({delay}) --", "MySQL"),
    ("'; WAITFOR DELAY '0:0:{delay}' --", "MSSQL"),
    ("' OR pg_sleep({delay}) --", "PostgreSQL"),
    ("' || (SELECT CASE WHEN 1=1 THEN SLEEP({delay}) ELSE 0 END) --", "MySQL"),
    ("1; SELECT SLEEP({delay})", "MySQL"),
]

# Database fingerprint patterns
DB_FINGERPRINTS = {
    'MySQL': [r'MySQL', r'mysql_', r'mysqli_', r'MariaDB'],
    'PostgreSQL': [r'PostgreSQL', r'pg_', r'PSQLException'],
    'MSSQL': [r'Microsoft.*SQL Server', r'sqlserver', r'ODBC.*Driver'],
    'Oracle': [r'ORA-\d{5}', r'Oracle.*Driver'],
    'SQLite': [r'SQLite'],
    'Access': [r'JET Database', r'Access Database'],
}


class SQLiScanner(BaseScanner):
    """
    SQL Injection scanner with differential response analysis.

    Uses three detection techniques:
    1. Error-based: Detects SQL errors in responses
    2. Boolean-blind: Compares true/false condition responses
    3. Time-based: Measures response time with baseline calibration
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        self._baseline_cache = {}
        logger.info(f"SQLi Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "SQLi"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load SQLi payloads from file."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / SQLI_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file, MAX_PAYLOADS_PER_INPUT)

        if not payloads:
            logger.warning("Payload file not found or empty. Using built-in payloads.")
            payloads = [
                "'", '"',
                "' OR '1'='1", "' OR '1'='1' --",
                "admin' --", "admin' #",
                "' AND '1'='1", "' AND '1'='2",
                "' OR SLEEP(5) --",
                "'; WAITFOR DELAY '0:0:5' --",
            ]

        return payloads

    def _check_sql_errors(self, response_text: str) -> Optional[str]:
        """Check response for SQL error patterns. Returns matched pattern or None."""
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        return None

    def _fingerprint_db(self, response_text: str) -> str:
        """Attempt to identify the database engine from error messages."""
        for db_name, patterns in DB_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_name
        return "Unknown"

    def _extract_error_evidence(self, response_text: str, error_pattern: str, max_length: int = 300) -> str:
        """Extract SQL error message from response."""
        try:
            match = re.search(error_pattern, response_text, re.IGNORECASE)
            if match:
                pos = match.start()
                start = max(0, pos - 50)
                end = min(len(response_text), pos + 200)
                return response_text[start:end].strip()[:max_length]
        except Exception as e:
            logger.debug(f"Failed to extract SQL error evidence: {e}")
        return f"SQL error pattern detected: {error_pattern}"

    def _response_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity ratio between two response bodies.
        Uses SequenceMatcher for content comparison.
        """
        # Truncate very long responses for performance
        max_compare = 10000
        t1 = text1[:max_compare]
        t2 = text2[:max_compare]
        return SequenceMatcher(None, t1, t2).ratio()

    def _measure_baseline(self, form: Form, field_name: str) -> Tuple[float, str]:
        """
        Measure baseline response time and content for a form.

        Returns:
            Tuple of (average_response_time, baseline_response_text)
        """
        cache_key = f"{form.action}:{field_name}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        times = []
        baseline_text = ""

        for i in range(SQLI_BASELINE_SAMPLES):
            form_data = self._build_form_data(form, field_name, f"baseline_test_{i}")
            start = time.time()
            response = self._submit_form(form, form_data)
            elapsed = time.time() - start
            times.append(elapsed)

            if response and i == 0:
                baseline_text = response.text

        avg_time = sum(times) / len(times) if times else 0
        result = (avg_time, baseline_text)
        self._baseline_cache[cache_key] = result
        return result

    def _check_error_based(self, form: Form, field, payload: str) -> Optional[Finding]:
        """Test for error-based SQLi."""
        form_data = self._build_form_data(form, field.name, payload)
        response = self._submit_form(form, form_data)

        if not response:
            return None

        error_pattern = self._check_sql_errors(response.text)
        if error_pattern:
            evidence = self._extract_error_evidence(response.text, error_pattern)
            db_engine = self._fingerprint_db(response.text)

            return Finding(
                vuln_type='SQLi',
                url=form.action,
                parameter=field.name,
                payload=payload,
                evidence=evidence,
                severity='CRITICAL',
                method=form.method,
                description=f'Error-based SQL Injection in {field.name} (DB: {db_engine})',
                remediation='Use parameterized queries (prepared statements) instead of string concatenation. '
                            'Implement input validation and use an ORM where possible.',
                cwe_id=CWE_MAPPINGS.get('SQLi', ''),
                owasp_category=OWASP_MAPPINGS.get('SQLi', ''),
                confidence='HIGH',
                scanner_module='SQLiScanner',
                context=f'database_engine={db_engine}',
                tags=['sqli', 'error-based', db_engine.lower()],
            )
        return None

    def _check_boolean_blind(self, form: Form, field) -> Optional[Finding]:
        """
        Test for boolean-blind SQLi using differential response analysis.

        Compares responses between true and false SQL conditions.
        If the true condition produces a significantly different response
        than the false condition, the parameter is likely injectable.
        """
        baseline_time, baseline_text = self._measure_baseline(form, field.name)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            # Submit true condition
            true_data = self._build_form_data(form, field.name, true_payload)
            true_response = self._submit_form(form, true_data)
            if not true_response:
                continue

            # Submit false condition
            false_data = self._build_form_data(form, field.name, false_payload)
            false_response = self._submit_form(form, false_data)
            if not false_response:
                continue

            # Compare responses
            true_vs_false = self._response_similarity(true_response.text, false_response.text)
            true_vs_baseline = self._response_similarity(true_response.text, baseline_text)
            false_vs_baseline = self._response_similarity(false_response.text, baseline_text)

            # If true and false responses differ significantly,
            # AND one of them matches baseline more than the other
            if true_vs_false < 0.85:
                # Significant difference between true and false
                if abs(true_vs_baseline - false_vs_baseline) > 0.1:
                    evidence = (
                        f"Boolean blind SQLi detected. "
                        f"True/False similarity: {true_vs_false:.2%}. "
                        f"True payload: {true_payload}, False payload: {false_payload}"
                    )
                    return Finding(
                        vuln_type='SQLi',
                        url=form.action,
                        parameter=field.name,
                        payload=true_payload,
                        evidence=evidence,
                        severity='HIGH',
                        method=form.method,
                        description=f'Boolean-blind SQL Injection in {field.name}',
                        remediation='Use parameterized queries (prepared statements). '
                                    'Never concatenate user input into SQL queries.',
                        cwe_id=CWE_MAPPINGS.get('SQLi', ''),
                        owasp_category=OWASP_MAPPINGS.get('SQLi', ''),
                        confidence='MEDIUM',
                        scanner_module='SQLiScanner',
                        context='boolean_blind',
                        tags=['sqli', 'boolean-blind'],
                    )
        return None

    def _check_time_based(self, form: Form, field) -> Optional[Finding]:
        """
        Test for time-based blind SQLi with baseline calibration.

        Measures baseline response time first, then checks if
        time-based payloads cause significant additional delay.
        """
        baseline_time, _ = self._measure_baseline(form, field.name)
        delay = SQLI_TIME_THRESHOLD

        for payload_template, db_hint in TIME_PAYLOADS:
            payload = payload_template.replace('{delay}', str(delay))
            form_data = self._build_form_data(form, field.name, payload)

            start = time.time()
            response = self._submit_form(form, form_data)
            elapsed = time.time() - start

            # Must be significantly longer than baseline
            if elapsed >= (baseline_time + delay - 1):
                evidence = (
                    f"Response delayed by {elapsed:.2f}s "
                    f"(baseline: {baseline_time:.2f}s, expected delay: {delay}s)"
                )
                return Finding(
                    vuln_type='SQLi',
                    url=form.action,
                    parameter=field.name,
                    payload=payload,
                    evidence=evidence,
                    severity='HIGH',
                    method=form.method,
                    description=f'Time-based SQL Injection in {field.name} (possible {db_hint})',
                    remediation='Use parameterized queries. Implement query timeout limits.',
                    cwe_id=CWE_MAPPINGS.get('SQLi', ''),
                    owasp_category=OWASP_MAPPINGS.get('SQLi', ''),
                    confidence='MEDIUM',
                    scanner_module='SQLiScanner',
                    context=f'time_based,db_hint={db_hint}',
                    tags=['sqli', 'time-based', db_hint.lower()],
                )
        return None

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan a form for SQL injection using multiple techniques."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for SQLi")

        testable_fields = self._get_testable_fields(form)
        if not testable_fields:
            logger.debug(f"No testable fields in form {form.action}")
            return findings

        for field in testable_fields:
            field_vulnerable = False

            # Technique 1: Error-based with file payloads
            for payload in self.payloads:
                if field_vulnerable:
                    break
                try:
                    finding = self._check_error_based(form, field, payload)
                    if finding:
                        findings.append(finding)
                        logger.warning(f"SQLi found in {form.action} param '{field.name}' (error-based)")
                        field_vulnerable = True
                except Exception as e:
                    logger.error(f"Error in error-based SQLi test: {e}")

            # Technique 2: Boolean-blind (differential analysis)
            if not field_vulnerable:
                try:
                    finding = self._check_boolean_blind(form, field)
                    if finding:
                        findings.append(finding)
                        logger.warning(f"SQLi found in {form.action} param '{field.name}' (boolean-blind)")
                        field_vulnerable = True
                except Exception as e:
                    logger.error(f"Error in boolean-blind SQLi test: {e}")

            # Technique 3: Time-based with baseline
            if not field_vulnerable:
                try:
                    finding = self._check_time_based(form, field)
                    if finding:
                        findings.append(finding)
                        logger.warning(f"SQLi found in {form.action} param '{field.name}' (time-based)")
                        field_vulnerable = True
                except Exception as e:
                    logger.error(f"Error in time-based SQLi test: {e}")

        return findings
