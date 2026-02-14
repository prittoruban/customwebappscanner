"""
Cross-Site Scripting (XSS) vulnerability scanner with context-aware detection.

Production features:
1. Canary-based context detection (HTML body, attribute, JavaScript, URL)
2. Context-specific payload selection for reduced false positives
3. Reflection verification ensuring payload came from our injection
4. Severity scoring based on context and exploitability
"""

import re
import uuid
import html
from typing import List, Optional, Tuple
from pathlib import Path

from scanner.base import BaseScanner
from crawler.crawler import Form
from models.finding import Finding
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    XSS_REFLECTION_PATTERNS,
    XSS_CONTEXTS,
    MAX_PAYLOADS_PER_INPUT,
    PAYLOAD_DIR,
    XSS_PAYLOAD_FILE,
    CWE_MAPPINGS,
    OWASP_MAPPINGS,
)

logger = get_logger(__name__)

# Context-specific payloads for targeted injection
CONTEXT_PAYLOADS = {
    'html_body': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
        '<marquee onstart=alert(1)>',
    ],
    'html_attribute': [
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onmouseover="alert(1)" style="position:fixed;width:100%;height:100%" ',
        '" ><script>alert(1)</script><"',
        "' ><script>alert(1)</script><'",
    ],
    'javascript': [
        "';alert(1);//",
        '";alert(1);//',
        '</script><script>alert(1)</script>',
        '\\";alert(1);//',
        '-alert(1)-',
        '`-alert(1)-`',
    ],
    'url': [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'javascript:alert(document.domain)',
    ],
    'generic': [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1);//",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
    ]
}


class XSSScanner(BaseScanner):
    """
    Context-aware XSS vulnerability scanner.

    Uses a canary probe to detect injection context before selecting
    targeted payloads, dramatically reducing false positives while
    improving detection accuracy.

    Detection flow:
    1. Inject unique canary string into each field
    2. Analyze where canary appears in response (context detection)
    3. Select context-appropriate payloads
    4. Verify payload reflection came from our injection
    5. Score severity based on context and exploitability
    """

    def __init__(
        self,
        http_client: HTTPClient,
        payload_file: Optional[Path] = None
    ):
        super().__init__(http_client)
        self.payloads = self._load_payloads(payload_file)
        logger.info(f"XSS Scanner initialized with {len(self.payloads)} payloads")

    @property
    def scanner_name(self) -> str:
        return "XSS"

    def _load_payloads(self, payload_file: Optional[Path]) -> List[str]:
        """Load XSS payloads from file."""
        if payload_file is None:
            payload_file = PAYLOAD_DIR / XSS_PAYLOAD_FILE

        payloads = self._load_payloads_from_file(payload_file, MAX_PAYLOADS_PER_INPUT)

        if not payloads:
            logger.warning("Payload file not found or empty. Using built-in payloads.")
            payloads = CONTEXT_PAYLOADS['generic']

        return payloads

    def _generate_canary(self) -> str:
        """Generate a unique canary string for context detection."""
        return f"xsscanary{uuid.uuid4().hex[:8]}"

    def _detect_context(self, canary: str, response_text: str) -> List[str]:
        """
        Detect the injection context(s) where the canary appears.

        Args:
            canary: The canary string to look for
            response_text: HTTP response body

        Returns:
            List of detected contexts
        """
        contexts = []

        if canary not in response_text:
            return contexts

        for context_name, pattern_template in XSS_CONTEXTS.items():
            pattern = pattern_template.replace('{CANARY}', re.escape(canary))
            try:
                if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                    contexts.append(context_name)
            except re.error:
                pass

        # If canary is reflected but no specific context matched
        if not contexts:
            contexts.append('html_body')

        return contexts

    def _get_payloads_for_context(self, contexts: List[str]) -> List[str]:
        """Select payloads appropriate for the detected injection contexts."""
        targeted_payloads = []
        seen = set()

        for ctx in contexts:
            for payload in CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS['generic']):
                if payload not in seen:
                    targeted_payloads.append(payload)
                    seen.add(payload)

        # Also include some generic payloads from the file
        for payload in self.payloads[:10]:
            if payload not in seen:
                targeted_payloads.append(payload)
                seen.add(payload)

        return targeted_payloads

    def _verify_reflection(self, payload: str, response_text: str) -> Tuple[bool, str]:
        """
        Verify that the payload is genuinely reflected, not a false positive.

        Returns:
            Tuple of (is_reflected, evidence_snippet)
        """
        # Check 1: Exact payload reflection (strongest signal)
        if payload in response_text:
            evidence = self._extract_evidence(payload, response_text)
            return True, evidence

        # Check 2: HTML-decoded reflection
        decoded_payload = html.unescape(payload)
        if decoded_payload != payload and decoded_payload in response_text:
            evidence = self._extract_evidence(decoded_payload, response_text)
            return True, evidence

        # Check 3: Partial critical reflection from OUR payload
        dangerous_patterns = [
            (r'<script[^>]*>', '<script'),
            (r'onerror\s*=', 'onerror='),
            (r'onload\s*=', 'onload='),
            (r'onfocus\s*=', 'onfocus='),
            (r'onmouseover\s*=', 'onmouseover='),
            (r'javascript\s*:', 'javascript:'),
        ]

        for regex, marker in dangerous_patterns:
            if marker.lower() in payload.lower():
                matches = list(re.finditer(regex, response_text, re.IGNORECASE))
                if matches:
                    for match in matches:
                        context = response_text[max(0, match.start() - 50):match.end() + 50]
                        payload_fragments = [
                            p.strip() for p in re.split(r'[<>"\'=\s]', payload) if len(p.strip()) > 3
                        ]
                        for frag in payload_fragments:
                            if frag.lower() in context.lower():
                                return True, context.strip()[:200]

        return False, ""

    def _extract_evidence(self, payload: str, response_text: str, max_length: int = 200) -> str:
        """Extract evidence snippet showing where payload was reflected."""
        try:
            pos = response_text.find(payload)
            if pos == -1:
                pos = response_text.lower().find(payload.lower())
            if pos != -1:
                start = max(0, pos - 50)
                end = min(len(response_text), pos + len(payload) + 50)
                return response_text[start:end].strip()[:max_length]
        except Exception as e:
            logger.debug(f"Failed to extract evidence: {e}")
        return "Payload reflected in response"

    def _calculate_severity(self, contexts: List[str], payload: str) -> str:
        """Calculate severity based on injection context and payload type."""
        if 'javascript' in contexts or '<script' in payload.lower():
            return 'CRITICAL'
        if 'html_attribute' in contexts and re.search(r'on\w+=', payload):
            return 'HIGH'
        if 'url' in contexts:
            return 'HIGH'
        return 'MEDIUM'

    def scan_form(self, form: Form) -> List[Finding]:
        """Scan a form for XSS using context-aware detection."""
        findings = []
        logger.info(f"Scanning form {form.method} {form.action} for XSS")

        testable_fields = self._get_testable_fields(form)
        if not testable_fields:
            logger.debug(f"No testable fields in form {form.action}")
            return findings

        for field in testable_fields:
            # Step 1: Inject canary to detect context
            canary = self._generate_canary()
            form_data = self._build_form_data(form, field.name, canary)

            try:
                response = self._submit_form(form, form_data)
                if not response:
                    continue

                # Step 2: Detect where canary appears
                contexts = self._detect_context(canary, response.text)
                if not contexts:
                    logger.debug(f"Canary not reflected for field {field.name}")
                    continue

                logger.debug(f"Field {field.name} reflected in contexts: {contexts}")

                # Step 3: Select and test context-appropriate payloads
                targeted_payloads = self._get_payloads_for_context(contexts)

                for payload in targeted_payloads:
                    form_data = self._build_form_data(form, field.name, payload)
                    resp = self._submit_form(form, form_data)
                    if not resp:
                        continue

                    # Step 4: Verify reflection
                    is_reflected, evidence = self._verify_reflection(payload, resp.text)

                    if is_reflected:
                        severity = self._calculate_severity(contexts, payload)
                        finding = Finding(
                            vuln_type='XSS',
                            url=form.action,
                            parameter=field.name,
                            payload=payload,
                            evidence=evidence,
                            severity=severity,
                            method=form.method,
                            description=f'Context-aware XSS in {field.name} (contexts: {", ".join(contexts)})',
                            remediation='Encode output based on context: HTML entity encode for HTML body, '
                                        'attribute encode for attributes, JavaScript encode for script contexts. '
                                        'Use Content-Security-Policy header to mitigate impact.',
                            cwe_id=CWE_MAPPINGS.get('XSS', ''),
                            owasp_category=OWASP_MAPPINGS.get('XSS', ''),
                            confidence='HIGH' if payload in resp.text else 'MEDIUM',
                            scanner_module='XSSScanner',
                            context=', '.join(contexts),
                            tags=['xss', 'reflected'] + contexts,
                        )
                        findings.append(finding)
                        logger.warning(
                            f"XSS found in {form.action} param '{field.name}' "
                            f"[{severity}] context={contexts}"
                        )
                        break  # First finding per field

            except Exception as e:
                logger.error(f"Error testing XSS on {form.action}: {e}")

        return findings
