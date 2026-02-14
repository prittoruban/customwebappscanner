"""
Cross-Site Request Forgery (CSRF) vulnerability scanner.

Production features:
1. Exact CSRF token name matching (no false positives on generic underscores)
2. Pattern-based token detection for non-standard field names
3. Token entropy analysis to verify tokens are truly random
4. State-change detection with improved heuristics
5. Optional active testing (submit without token)
"""

import math
import re
from typing import List, Set
from collections import Counter

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    CSRF_TOKEN_NAMES,
    CSRF_TOKEN_PATTERNS,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)


class CSRFScanner(BaseScanner):
    """
    CSRF vulnerability scanner with token analysis.

    Detection methodology:
    1. Identify POST forms that perform state changes
    2. Check for CSRF token presence using exact name matching
    3. Check hidden fields against token patterns
    4. Analyze token entropy to detect weak/static tokens
    5. Optionally test submission without token
    """

    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.csrf_token_names = set(name.lower() for name in CSRF_TOKEN_NAMES)
        self.csrf_token_patterns = [p.lower() for p in CSRF_TOKEN_PATTERNS]
        logger.info("CSRF Scanner initialized")

    @property
    def scanner_name(self) -> str:
        return "CSRF"

    def _calculate_entropy(self, value: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy indicates more randomness (good for tokens).

        Args:
            value: String to analyze

        Returns:
            Entropy value (bits per character)
        """
        if not value:
            return 0.0

        freq = Counter(value)
        length = len(value)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        return entropy

    def _has_csrf_token(self, form: Form) -> dict:
        """
        Check if form contains a CSRF token field.

        Returns a dict with:
        - 'found': bool - whether a token was found
        - 'field_name': str - name of the token field (if found)
        - 'token_value': str - value of the token (if found)
        - 'entropy': float - entropy of the token value
        - 'weak': bool - whether the token appears weak
        """
        result = {
            'found': False,
            'field_name': '',
            'token_value': '',
            'entropy': 0.0,
            'weak': False,
        }

        field_names = {f.name.lower(): f for f in form.fields if f.name}

        # Check 1: Exact name match against known CSRF token names
        for token_name in self.csrf_token_names:
            if token_name in field_names:
                field = field_names[token_name]
                result['found'] = True
                result['field_name'] = field.name
                result['token_value'] = field.value
                result['entropy'] = self._calculate_entropy(field.value)
                # Token is weak if entropy is very low or value is too short
                result['weak'] = result['entropy'] < 3.0 or len(field.value) < 16
                return result

        # Check 2: Pattern match on hidden fields
        for field in form.fields:
            if field.field_type == 'hidden' and field.value and field.name:
                name_lower = field.name.lower()
                # Check against known CSRF patterns (not just any underscore)
                for pattern in self.csrf_token_patterns:
                    if pattern in name_lower:
                        result['found'] = True
                        result['field_name'] = field.name
                        result['token_value'] = field.value
                        result['entropy'] = self._calculate_entropy(field.value)
                        result['weak'] = result['entropy'] < 3.0 or len(field.value) < 16
                        return result

        return result

    def _is_state_changing(self, form: Form) -> bool:
        """
        Determine if form is likely to perform state-changing operations.

        Improved heuristics with better classification.
        """
        # Only POST forms are typically state-changing
        if form.method != 'POST':
            return False

        url_lower = form.action.lower()

        # Exclude read-only patterns
        safe_patterns = ['search', 'filter', 'query', 'find', 'lookup', 'check', 'browse']
        for pattern in safe_patterns:
            if pattern in url_lower:
                return False

        # Check for state-changing verbs in URL
        state_changing_verbs = [
            'create', 'add', 'new', 'insert',
            'update', 'edit', 'modify', 'change',
            'delete', 'remove', 'destroy',
            'submit', 'post', 'send', 'save',
            'login', 'register', 'signup', 'logout',
            'transfer', 'payment', 'checkout', 'order',
            'approve', 'reject', 'confirm', 'cancel',
            'upload', 'import', 'export',
        ]

        for verb in state_changing_verbs:
            if verb in url_lower:
                return True

        # Check field names for state-changing patterns
        field_names = ' '.join(f.name.lower() for f in form.fields if f.name)
        password_fields = any(f.field_type == 'password' for f in form.fields)

        if password_fields:
            return True  # Login/registration forms are state-changing

        for verb in state_changing_verbs:
            if verb in field_names:
                return True

        # Default: POST forms without safe patterns are likely state-changing
        return True

    def _test_without_token(self, form: Form) -> bool:
        """
        Test if form submission succeeds without CSRF token.

        Returns True if submission succeeded (indicating vulnerability).
        """
        form_data = {}
        for field in form.fields:
            name_lower = field.name.lower() if field.name else ''
            # Skip token fields
            if name_lower in self.csrf_token_names:
                continue
            skip = False
            for pattern in self.csrf_token_patterns:
                if pattern in name_lower:
                    skip = True
                    break
            if skip:
                continue
            form_data[field.name] = field.value if field.value else 'test'

        try:
            response = self.http_client.post(form.action, data=form_data)
            if not response:
                return False

            if 200 <= response.status_code < 400:
                response_lower = response.text.lower()
                # Check for rejection indicators
                rejection_indicators = [
                    'csrf', 'token', 'forbidden', '403',
                    'invalid token', 'missing token', 'verification failed'
                ]
                for indicator in rejection_indicators:
                    if indicator in response_lower:
                        return False
                return True
        except Exception as e:
            logger.error(f"Error testing CSRF on {form.action}: {e}")

        return False

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan a form for CSRF vulnerabilities."""
        findings = []

        if not self._is_state_changing(form):
            logger.debug(f"Skipping non-state-changing form: {form.action}")
            return findings

        logger.info(f"Scanning form {form.method} {form.action} for CSRF")

        token_info = self._has_csrf_token(form)

        if not token_info['found']:
            # No CSRF token found
            # Optionally verify by testing without token
            active_test = self._test_without_token(form)

            severity = 'HIGH' if active_test else 'MEDIUM'
            confidence = 'HIGH' if active_test else 'MEDIUM'
            evidence = 'No CSRF token field found in form'
            if active_test:
                evidence += '. Form accepted submission without token.'

            finding = Finding(
                vuln_type='CSRF',
                url=form.action,
                parameter='N/A',
                payload='N/A',
                evidence=evidence,
                severity=severity,
                method=form.method,
                description='Form lacks CSRF protection token',
                remediation='Implement anti-CSRF tokens using a framework-provided mechanism '
                            '(e.g., Django CSRF middleware, Rails authenticity_token). '
                            'Use SameSite cookie attribute as defense-in-depth.',
                cwe_id=CWE_MAPPINGS.get('CSRF', ''),
                owasp_category=OWASP_MAPPINGS.get('CSRF', ''),
                confidence=confidence,
                scanner_module='CSRFScanner',
                tags=['csrf', 'missing-token'],
            )
            findings.append(finding)
            logger.warning(f"CSRF token missing in form: {form.action}")

        elif token_info['weak']:
            # Token found but appears weak
            finding = Finding(
                vuln_type='CSRF',
                url=form.action,
                parameter=token_info['field_name'],
                payload='N/A',
                evidence=f"CSRF token has low entropy ({token_info['entropy']:.2f} bits/char) "
                         f"or short length ({len(token_info['token_value'])} chars). "
                         f"Token field: {token_info['field_name']}",
                severity='LOW',
                method=form.method,
                description='CSRF token appears weak (low entropy or short length)',
                remediation='Generate CSRF tokens using a cryptographically secure PRNG '
                            'with at least 128 bits of entropy. Ensure tokens are unique per session.',
                cwe_id=CWE_MAPPINGS.get('CSRF', ''),
                owasp_category=OWASP_MAPPINGS.get('CSRF', ''),
                confidence='LOW',
                scanner_module='CSRFScanner',
                tags=['csrf', 'weak-token'],
            )
            findings.append(finding)
            logger.warning(f"Weak CSRF token in form: {form.action}")
        else:
            logger.debug(f"CSRF token present in form: {form.action}")

        return findings
