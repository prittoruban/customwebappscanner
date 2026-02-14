"""
Vulnerability Chain Detection Engine.

Analyzes findings to identify chains of vulnerabilities that, when combined,
create higher-impact attack paths. This is a unique market differentiator
that no existing open-source scanner provides.

Examples of chains:
- Open Redirect + XSS = Phishing amplification
- SSRF + LFI = Internal file read via server
- SQLi + Weak Headers = Data exfiltration without CSP blocking
- CSRF + Missing SameSite = Cross-origin state manipulation
"""

import uuid
from typing import List, Dict, Tuple
from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)

# Chain rules: (vuln_type_1, vuln_type_2, chain_description, severity_upgrade, tags)
CHAIN_RULES = [
    {
        'requires': ['XSS', 'Security Headers'],
        'condition': lambda findings: (
            any(f.vuln_type == 'XSS' for f in findings) and
            any(f.vuln_type == 'Security Headers' and 'Content-Security-Policy' in f.parameter
                for f in findings)
        ),
        'name': 'XSS + Missing CSP',
        'description': 'XSS vulnerability combined with missing Content-Security-Policy header '
                       'allows unrestricted script execution including data exfiltration via '
                       'external requests.',
        'severity': 'CRITICAL',
        'remediation': 'Fix XSS vulnerabilities AND implement a strict Content-Security-Policy. '
                       'CSP acts as defense-in-depth even if XSS slips through.',
        'tags': ['chain', 'xss-csp'],
    },
    {
        'requires': ['CSRF', 'Security Headers'],
        'condition': lambda findings: (
            any(f.vuln_type == 'CSRF' for f in findings) and
            any(f.vuln_type == 'Security Headers' and 'samesite' in str(f.tags)
                for f in findings)
        ),
        'name': 'CSRF + Missing SameSite Cookies',
        'description': 'CSRF vulnerability amplified by cookies missing SameSite attribute, '
                       'enabling cross-origin state-changing requests with full session credentials.',
        'severity': 'HIGH',
        'remediation': 'Implement CSRF tokens AND set SameSite=Lax or Strict on session cookies.',
        'tags': ['chain', 'csrf-samesite'],
    },
    {
        'requires': ['Open Redirect', 'XSS'],
        'condition': lambda findings: (
            any(f.vuln_type == 'Open Redirect' for f in findings) and
            any(f.vuln_type == 'XSS' for f in findings)
        ),
        'name': 'Open Redirect + XSS',
        'description': 'Open redirect can be chained with XSS to create convincing phishing attacks. '
                       'The trusted domain in the URL bar increases victim trust while executing XSS.',
        'severity': 'HIGH',
        'remediation': 'Fix both the open redirect and XSS vulnerabilities. Validate redirect targets '
                       'against an allowlist.',
        'tags': ['chain', 'redirect-xss', 'phishing'],
    },
    {
        'requires': ['SQLi', 'Security Headers'],
        'condition': lambda findings: (
            any(f.vuln_type == 'SQLi' for f in findings) and
            any(f.vuln_type == 'Security Headers' and 'Strict-Transport-Security' in f.parameter
                for f in findings)
        ),
        'name': 'SQLi + Missing HSTS',
        'description': 'SQL Injection combined with missing HSTS allows MITM attackers to '
                       'intercept database queries and results over downgraded HTTP connections.',
        'severity': 'CRITICAL',
        'remediation': 'Fix SQLi with parameterized queries AND enforce HTTPS with HSTS header.',
        'tags': ['chain', 'sqli-hsts'],
    },
    {
        'requires': ['SSRF', 'LFI'],
        'condition': lambda findings: (
            any(f.vuln_type == 'SSRF' for f in findings) and
            any(f.vuln_type == 'LFI' for f in findings)
        ),
        'name': 'SSRF + LFI',
        'description': 'SSRF and LFI vulnerabilities together enable reading internal files via server '
                       'and potentially pivoting to internal services, creating a full server compromise path.',
        'severity': 'CRITICAL',
        'remediation': 'Address both vulnerabilities. Implement strict URL validation for SSRF and '
                       'file path validation for LFI.',
        'tags': ['chain', 'ssrf-lfi', 'server-compromise'],
    },
    {
        'requires': ['RCE'],
        'condition': lambda findings: (
            any(f.vuln_type == 'RCE' for f in findings) and
            any(f.vuln_type == 'Security Headers' for f in findings)
        ),
        'name': 'Command Injection + Missing Security Headers',
        'description': 'Command injection vulnerability with missing security headers indicates '
                       'overall weak security posture and likely full server compromise.',
        'severity': 'CRITICAL',
        'remediation': 'Command injection is critical — fix immediately by eliminating shell commands. '
                       'Implement security headers as defense-in-depth.',
        'tags': ['chain', 'rce-headers', 'server-compromise'],
    },
    {
        'requires': ['XSS', 'CSRF'],
        'condition': lambda findings: (
            any(f.vuln_type == 'XSS' for f in findings) and
            any(f.vuln_type == 'CSRF' for f in findings)
        ),
        'name': 'XSS + CSRF',
        'description': 'XSS can be used to bypass CSRF protections by extracting CSRF tokens '
                       'from the DOM, enabling automated state-changing attacks.',
        'severity': 'CRITICAL',
        'remediation': 'Fix both XSS and CSRF. XSS alone can bypass all client-side CSRF protections.',
        'tags': ['chain', 'xss-csrf'],
    },
]


class VulnChainDetector:
    """
    Detects vulnerability chains — combinations of findings that create
    higher-impact attack paths than individual vulnerabilities.

    This is an analysis-only component that runs after all scanners complete.
    It does not make any HTTP requests.
    """

    def __init__(self):
        logger.info("Vulnerability Chain Detector initialized")

    def detect_chains(self, findings: List[Finding]) -> List[Finding]:
        """
        Analyze findings for vulnerability chains.

        Args:
            findings: All findings from all scanners

        Returns:
            List of chain findings (new Finding objects representing chains)
        """
        chain_findings = []
        vuln_types = set(f.vuln_type for f in findings)

        for rule in CHAIN_RULES:
            # Quick check: are the required vuln types present?
            if not all(vt in vuln_types for vt in rule['requires']):
                continue

            # Detailed condition check
            try:
                if rule['condition'](findings):
                    chain_id = f"chain-{uuid.uuid4().hex[:8]}"

                    # Find the related findings
                    related_urls = set()
                    for f in findings:
                        if f.vuln_type in rule['requires']:
                            related_urls.add(f.url)
                            # Tag original findings with chain reference
                            if f.chain_id is None:
                                f.chain_id = chain_id

                    chain_finding = Finding(
                        vuln_type='Vulnerability Chain',
                        url=', '.join(list(related_urls)[:3]),
                        parameter='Multiple',
                        payload='N/A',
                        evidence=f"Chain: {rule['name']}. "
                                 f"Involves {len(related_urls)} affected endpoint(s).",
                        severity=rule['severity'],
                        method='N/A',
                        description=rule['description'],
                        remediation=rule['remediation'],
                        confidence='HIGH',
                        scanner_module='VulnChainDetector',
                        chain_id=chain_id,
                        tags=rule['tags'],
                    )
                    chain_findings.append(chain_finding)
                    logger.warning(f"Vulnerability chain detected: {rule['name']}")

            except Exception as e:
                logger.error(f"Error evaluating chain rule '{rule.get('name', 'unknown')}': {e}")

        logger.info(f"Chain detection complete. Found {len(chain_findings)} chains")
        return chain_findings
