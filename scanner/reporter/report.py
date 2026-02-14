"""
Report generation and aggregation for vulnerability findings.

Supports multiple output formats:
- Console with color-coded severity and chain/remediation sections
- HTML report via Jinja2 (rich template with CWE, OWASP, chains, remediation)
- JSON report for machine-readable / CI integration
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter
from jinja2 import Environment, FileSystemLoader, select_autoescape

from models.finding import Finding
from utils.logger import get_logger
from config import TEMPLATE_DIR, REPORT_DIR, SEVERITY_LEVELS

logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates vulnerability scan reports in multiple formats.

    New in v2.0:
    - Vulnerability chain sections
    - Remediation code blocks
    - CWE / OWASP category mapping
    - Confidence levels
    """

    def __init__(self):
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        logger.info("Report generator initialized")

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def _calculate_statistics(self, findings: List[Finding]) -> Dict[str, Any]:
        if not findings:
            return {
                'total_vulnerabilities': 0,
                'by_type': {},
                'by_severity': {},
                'unique_urls': 0,
                'risk_score': 0,
                'chains': 0,
            }

        by_type = Counter(f.vuln_type for f in findings)
        by_severity = Counter(f.severity for f in findings)
        unique_urls = len(set(f.url for f in findings))
        risk_score = sum(SEVERITY_LEVELS.get(f.severity, 1) for f in findings)
        chains = len(set(f.chain_id for f in findings if f.chain_id))

        return {
            'total_vulnerabilities': len(findings),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'unique_urls': unique_urls,
            'risk_score': risk_score,
            'chains': chains,
        }

    def _sort_findings(self, findings: List[Finding]) -> List[Finding]:
        order = {s: i for i, s in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])}
        return sorted(findings, key=lambda f: (order.get(f.severity, 999), f.vuln_type, f.url))

    # ------------------------------------------------------------------
    # Console
    # ------------------------------------------------------------------
    def generate_console_report(self, findings: List[Finding], target_url: str):
        stats = self._calculate_statistics(findings)
        sep = "=" * 72

        print(f"\n{sep}")
        print("  VULNERABILITY SCAN REPORT  (v2.0)")
        print(sep)
        print(f"  Target : {target_url}")
        print(f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(sep)

        print(f"\n  Total Findings : {stats['total_vulnerabilities']}")
        print(f"  Risk Score     : {stats['risk_score']}")
        print(f"  Vuln Chains    : {stats['chains']}")
        print(f"  Affected URLs  : {stats['unique_urls']}")

        if stats['by_severity']:
            print("\n  By Severity:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                cnt = stats['by_severity'].get(sev, 0)
                if cnt:
                    print(f"    {sev:10s} : {cnt}")

        if stats['by_type']:
            print("\n  By Type:")
            for vt, cnt in sorted(stats['by_type'].items()):
                print(f"    {vt:25s} : {cnt}")

        # Top findings
        if findings:
            sorted_f = self._sort_findings(findings)
            print(f"\n{'-' * 72}")
            print("  TOP FINDINGS")
            print(f"{'-' * 72}")

            for i, f in enumerate(sorted_f[:15], 1):
                payload_display = f.payload[:80]
                if len(f.payload) > 80:
                    payload_display += "..."
                cwe = f"  CWE-{f.cwe_id}" if f.cwe_id else ""
                owasp = f"  {f.owasp_category}" if f.owasp_category else ""

                print(f"\n  {i}. [{f.severity}] {f.vuln_type}{cwe}{owasp}")
                print(f"     URL      : {f.url}")
                print(f"     Parameter: {f.parameter}")
                print(f"     Payload  : {payload_display}")
                if f.confidence:
                    print(f"     Confidence: {f.confidence}")
                if f.chain_id:
                    print(f"     Chain    : {f.chain_id}")

            # Chains summary
            chain_ids = set(f.chain_id for f in findings if f.chain_id)
            if chain_ids:
                print(f"\n{'-' * 72}")
                print("  VULNERABILITY CHAINS")
                print(f"{'-' * 72}")
                for cid in sorted(chain_ids):
                    members = [f for f in findings if f.chain_id == cid]
                    types = ", ".join(set(f.vuln_type for f in members))
                    print(f"\n  Chain: {cid}")
                    print(f"    Types: {types}")
                    print(f"    Count: {len(members)} linked findings")

            # Show one remediation sample
            remediated = [f for f in findings if f.remediation]
            if remediated:
                print(f"\n{'-' * 72}")
                print("  REMEDIATION (sample)")
                print(f"{'-' * 72}")
                sample = remediated[0]
                # Show first 20 lines
                lines = sample.remediation.split('\n')[:20]
                for line in lines:
                    print(f"  {line}")
                if len(sample.remediation.split('\n')) > 20:
                    print("  ... (see full report for details)")

        print(f"\n{sep}")

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def generate_html_report(
        self,
        findings: List[Finding],
        target_url: str,
        output_file: Path = None
    ) -> Path:
        logger.info("Generating HTML report...")

        stats = self._calculate_statistics(findings)
        sorted_findings = self._sort_findings(findings)

        # Collect chain info
        chain_ids = sorted(set(f.chain_id for f in findings if f.chain_id))
        chains = []
        for cid in chain_ids:
            members = [f for f in findings if f.chain_id == cid]
            chains.append({
                'id': cid,
                'types': list(set(f.vuln_type for f in members)),
                'count': len(members),
                'severity': members[0].severity if members else 'MEDIUM',
            })

        context = {
            'target_url': target_url,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': stats,
            'findings': sorted_findings,
            'total_findings': len(findings),
            'chains': chains,
            'scanner_version': '2.0',
        }

        try:
            template = self.jinja_env.get_template('report.html')
            html_content = template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render HTML template: {e}")
            raise

        if output_file is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = REPORT_DIR / f"scan_report_{ts}.html"

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as fh:
            fh.write(html_content)

        logger.info(f"HTML report saved to: {output_file}")
        return output_file

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    def generate_json_report(
        self,
        findings: List[Finding],
        target_url: str,
        output_file: Path = None
    ) -> Path:
        logger.info("Generating JSON report...")

        stats = self._calculate_statistics(findings)
        findings_data = []
        for f in findings:
            fd = {
                'type': f.vuln_type,
                'url': f.url,
                'parameter': f.parameter,
                'payload': f.payload,
                'evidence': f.evidence,
                'severity': f.severity,
                'method': f.method,
                'description': f.description,
                'cwe_id': f.cwe_id,
                'owasp_category': f.owasp_category,
                'confidence': f.confidence,
                'scanner_module': f.scanner_module,
                'context': f.context,
                'chain_id': f.chain_id,
                'remediation': f.remediation,
                'tags': f.tags,
            }
            findings_data.append(fd)

        report = {
            'scan_info': {
                'target_url': target_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '2.0',
            },
            'statistics': stats,
            'findings': findings_data,
        }

        if output_file is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = REPORT_DIR / f"scan_report_{ts}.json"

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, default=str)

        logger.info(f"JSON report saved to: {output_file}")
        return output_file

    # ------------------------------------------------------------------
    # Multi-format dispatcher
    # ------------------------------------------------------------------
    def generate_reports(
        self,
        findings: List[Finding],
        target_url: str,
        formats: List[str] = None
    ) -> Dict[str, Path]:
        if formats is None:
            formats = ['console']

        output_files = {}

        if 'console' in formats or not formats:
            self.generate_console_report(findings, target_url)

        if 'html' in formats or 'both' in formats:
            html_file = self.generate_html_report(findings, target_url)
            output_files['html'] = html_file

        if 'json' in formats or 'both' in formats:
            json_file = self.generate_json_report(findings, target_url)
            output_files['json'] = json_file

        return output_files
