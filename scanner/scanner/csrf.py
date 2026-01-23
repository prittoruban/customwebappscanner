"""
Cross-Site Request Forgery (CSRF) vulnerability scanner.

Detects missing CSRF protection by:
1. Identifying state-changing forms (POST requests)
2. Checking for presence of CSRF tokens in form fields
3. Testing if requests succeed without valid tokens
"""

from typing import List, Set
from crawler.crawler import Form
from utils.http import HTTPClient
from utils.logger import get_logger
from config import CSRF_TOKEN_NAMES
from scanner.xss import Finding  # Reuse Finding dataclass

logger = get_logger(__name__)


class CSRFScanner:
    """
    CSRF vulnerability scanner.
    
    Testing methodology:
    1. Identify POST forms (typically state-changing)
    2. Check if form contains CSRF token fields
    3. If no token found, flag as vulnerable
    4. Optionally test by submitting without token
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize CSRF scanner.
        
        Args:
            http_client: HTTP client for making requests
        """
        self.http_client = http_client
        self.csrf_token_names = set(name.lower() for name in CSRF_TOKEN_NAMES)
        logger.info(f"CSRF Scanner initialized")
    
    def _has_csrf_token(self, form: Form) -> bool:
        """
        Check if form contains a CSRF token field.
        
        Args:
            form: Form to check
            
        Returns:
            True if CSRF token field found, False otherwise
        """
        field_names = set(f.name.lower() for f in form.fields if f.name)
        
        # Check if any field name matches known CSRF token patterns
        for token_name in self.csrf_token_names:
            if token_name in field_names:
                logger.debug(f"CSRF token found in form: {token_name}")
                return True
        
        # Check for hidden fields that might be tokens
        for field in form.fields:
            if field.field_type == 'hidden' and field.value:
                # Check if field name suggests it's a token
                name_lower = field.name.lower()
                if 'token' in name_lower or 'csrf' in name_lower or '_' in name_lower:
                    logger.debug(f"Potential CSRF token field: {field.name}")
                    return True
        
        return False
    
    def _is_state_changing(self, form: Form) -> bool:
        """
        Determine if form is likely to perform state-changing operations.
        
        State-changing forms typically:
        - Use POST method
        - Contain action verbs in URL (create, update, delete, submit, etc.)
        - Are not search or filter forms
        
        Args:
            form: Form to check
            
        Returns:
            True if form likely performs state changes
        """
        # POST forms are typically state-changing
        if form.method != 'POST':
            return False
        
        # Check URL for non-state-changing patterns
        url_lower = form.action.lower()
        safe_patterns = ['search', 'filter', 'query', 'find']
        
        for pattern in safe_patterns:
            if pattern in url_lower:
                logger.debug(f"Form appears to be read-only: {pattern} in URL")
                return False
        
        # Check for state-changing verbs
        state_changing_verbs = [
            'create', 'add', 'new', 'insert',
            'update', 'edit', 'modify', 'change',
            'delete', 'remove', 'destroy',
            'submit', 'post', 'send', 'save',
            'login', 'register', 'signup', 'logout'
        ]
        
        for verb in state_changing_verbs:
            if verb in url_lower:
                logger.debug(f"State-changing form detected: {verb} in URL")
                return True
        
        # Check field names for state-changing patterns
        field_names = ' '.join(f.name.lower() for f in form.fields if f.name)
        for verb in state_changing_verbs:
            if verb in field_names:
                return True
        
        # Default: assume POST forms are state-changing
        return True
    
    def _test_without_token(self, form: Form) -> bool:
        """
        Test if form submission succeeds without CSRF token.
        
        Args:
            form: Form to test
            
        Returns:
            True if submission succeeded (indicating vulnerability)
        """
        # Build form data without CSRF token
        form_data = {}
        for field in form.fields:
            # Skip token fields
            if field.name.lower() in self.csrf_token_names:
                continue
            # Use test values for other fields
            form_data[field.name] = field.value if field.value else 'test'
        
        try:
            # Submit form
            response = self.http_client.post(form.action, data=form_data)
            
            if not response:
                return False
            
            # Check if request succeeded (2xx or 3xx status)
            if 200 <= response.status_code < 400:
                # Additional check: response shouldn't contain error messages
                error_indicators = ['csrf', 'token', 'invalid', 'error', 'forbidden']
                response_lower = response.text.lower()
                
                # If response contains error messages about tokens, not vulnerable
                for indicator in error_indicators:
                    if indicator in response_lower and 'token' in response_lower:
                        logger.debug(f"Form rejected submission without token")
                        return False
                
                logger.debug(f"Form accepted submission without token")
                return True
        
        except Exception as e:
            logger.error(f"Error testing CSRF on {form.action}: {e}")
        
        return False
    
    def scan_form(self, form: Form) -> List[Finding]:
        """
        Scan a single form for CSRF vulnerabilities.
        
        Args:
            form: Form object to test
            
        Returns:
            List of Finding objects (empty or single finding)
        """
        findings = []
        
        # Only scan POST forms that likely perform state changes
        if not self._is_state_changing(form):
            logger.debug(f"Skipping non-state-changing form: {form.action}")
            return findings
        
        logger.info(f"Scanning form {form.method} {form.action} for CSRF")
        
        # Check for CSRF token
        has_token = self._has_csrf_token(form)
        
        if not has_token:
            # Form lacks CSRF protection - potential vulnerability
            logger.warning(f"CSRF token missing in form: {form.action}")
            
            # Optionally test by submitting without token
            # (Disabled by default to avoid unintended state changes)
            # vulnerable = self._test_without_token(form)
            
            # For demo purposes, flag as vulnerable if token is missing
            finding = Finding(
                vuln_type='CSRF',
                url=form.action,
                parameter='N/A',
                payload='N/A',
                evidence='No CSRF token field found in form',
                severity='MEDIUM',
                method=form.method,
                description='Form lacks CSRF protection token'
            )
            findings.append(finding)
        else:
            logger.debug(f"CSRF token present in form: {form.action}")
        
        return findings
    
    def scan(self, forms: List[Form]) -> List[Finding]:
        """
        Scan multiple forms for CSRF vulnerabilities.
        
        Args:
            forms: List of Form objects to scan
            
        Returns:
            List of all CSRF findings
        """
        all_findings = []
        
        for form in forms:
            findings = self.scan_form(form)
            all_findings.extend(findings)
        
        logger.info(f"CSRF scan complete. Found {len(all_findings)} vulnerabilities")
        return all_findings
