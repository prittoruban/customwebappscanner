"""
Standardized vulnerability finding and scan result models.

Central data structures used across all scanner modules for consistent
vulnerability reporting, severity classification, and remediation guidance.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class SeverityLevel(Enum):
    """Vulnerability severity levels with numeric weights for scoring."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __lt__(self, other):
        if isinstance(other, SeverityLevel):
            return self.value < other.value
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, SeverityLevel):
            return self.value <= other.value
        return NotImplemented


@dataclass
class Finding:
    """
    Standardized vulnerability finding.

    Used across all scanner modules for consistent reporting.
    All scanners produce Finding objects which flow into the reporting engine.
    """
    vuln_type: str          # XSS, SQLi, CSRF, SSRF, LFI, RCE, etc.
    url: str                # URL where vulnerability was found
    parameter: str          # Vulnerable parameter name
    payload: str            # Payload that triggered the vulnerability
    evidence: str           # Evidence snippet from response
    severity: str           # LOW, MEDIUM, HIGH, CRITICAL
    method: str = "GET"     # HTTP method used
    description: str = ""   # Human-readable description
    remediation: str = ""   # Suggested fix / remediation guidance
    cwe_id: str = ""        # CWE identifier (e.g., "CWE-79")
    owasp_category: str = ""  # OWASP Top 10 category
    confidence: str = "MEDIUM"  # Detection confidence: LOW, MEDIUM, HIGH
    scanner_module: str = ""    # Which scanner found this
    context: str = ""       # Injection context (e.g., "html_attribute", "sql_string")
    chain_id: Optional[str] = None  # For linking chained vulnerabilities
    raw_request: str = ""   # Raw HTTP request for reproduction
    raw_response: str = ""  # Raw HTTP response snippet
    tags: List[str] = field(default_factory=list)  # Searchable tags


@dataclass
class ScanResult:
    """
    Aggregated result from a complete scan session.

    Contains all findings plus metadata about the scan itself.
    """
    target_url: str
    findings: List[Finding] = field(default_factory=list)
    scan_duration: float = 0.0  # seconds
    urls_crawled: int = 0
    forms_discovered: int = 0
    requests_made: int = 0
    errors: List[str] = field(default_factory=list)
    scanner_version: str = "2.0.0"
    scan_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'CRITICAL')

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'HIGH')

    @property
    def risk_score(self) -> int:
        """Weighted risk score based on severity levels."""
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return sum(weights.get(f.severity, 1) for f in self.findings)
