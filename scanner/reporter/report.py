"""
Report generation and aggregation for vulnerability findings.

Supports multiple output formats:
- HTML report with Jinja2 templates
- JSON report for machine-readable output
- Console output with summary statistics
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter
from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.xss import Finding
from utils.logger import get_logger
from config import TEMPLATE_DIR, REPORT_DIR, SEVERITY_LEVELS

logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates vulnerability scan reports in multiple formats.
    
    Features:
    - HTML reports with styled tables
    - JSON reports for automation
    - Summary statistics
    - Severity classification
    """
    
    def __init__(self):
        """Initialize report generator with Jinja2 environment."""
        # Setup Jinja2 for HTML templating
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        logger.info("Report generator initialized")
    
    def _calculate_statistics(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate summary statistics from findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dictionary with statistics
        """
        if not findings:
            return {
                'total_vulnerabilities': 0,
                'by_type': {},
                'by_severity': {},
                'unique_urls': 0,
                'risk_score': 0
            }
        
        # Count by vulnerability type
        by_type = Counter(f.vuln_type for f in findings)
        
        # Count by severity
        by_severity = Counter(f.severity for f in findings)
        
        # Count unique URLs
        unique_urls = len(set(f.url for f in findings))
        
        # Calculate risk score (weighted by severity)
        risk_score = sum(
            SEVERITY_LEVELS.get(f.severity, 1) for f in findings
        )
        
        return {
            'total_vulnerabilities': len(findings),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'unique_urls': unique_urls,
            'risk_score': risk_score
        }
    
    def _sort_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Sort findings by severity (highest first), then by type.
        
        Args:
            findings: List of findings
            
        Returns:
            Sorted list of findings
        """
        severity_order = {s: i for i, s in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])}
        
        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.severity, 999),
                f.vuln_type,
                f.url
            )
        )
    
    def generate_console_report(self, findings: List[Finding], target_url: str):
        """
        Print summary report to console.
        
        Args:
            findings: List of vulnerability findings
            target_url: Target URL that was scanned
        """
        stats = self._calculate_statistics(findings)
        
        print("\n" + "=" * 70)
        print("VULNERABILITY SCAN REPORT")
        print("=" * 70)
        print(f"Target: {target_url}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        print(f"\nTotal Vulnerabilities Found: {stats['total_vulnerabilities']}")
        
        if stats['by_severity']:
            print("\nBy Severity:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = stats['by_severity'].get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")
        
        if stats['by_type']:
            print("\nBy Type:")
            for vuln_type, count in stats['by_type'].items():
                print(f"  {vuln_type}: {count}")
        
        print(f"\nUnique URLs Affected: {stats['unique_urls']}")
        print(f"Risk Score: {stats['risk_score']}")
        
        # Display top findings
        if findings:
            print("\n" + "-" * 70)
            print("TOP FINDINGS:")
            print("-" * 70)
            
            sorted_findings = self._sort_findings(findings)
            for i, finding in enumerate(sorted_findings[:10], 1):  # Show top 10
                print(f"\n{i}. [{finding.severity}] {finding.vuln_type}")
                print(f"   URL: {finding.url}")
                print(f"   Parameter: {finding.parameter}")
                print(f"   Payload: {finding.payload[:100]}...")
        
        print("\n" + "=" * 70)
    
    def generate_html_report(
        self,
        findings: List[Finding],
        target_url: str,
        output_file: Path = None
    ) -> Path:
        """
        Generate HTML report using Jinja2 template.
        
        Args:
            findings: List of vulnerability findings
            target_url: Target URL that was scanned
            output_file: Output file path (auto-generated if None)
            
        Returns:
            Path to generated HTML report
        """
        logger.info("Generating HTML report...")
        
        # Calculate statistics
        stats = self._calculate_statistics(findings)
        
        # Sort findings by severity
        sorted_findings = self._sort_findings(findings)
        
        # Prepare template context
        context = {
            'target_url': target_url,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': stats,
            'findings': sorted_findings,
            'total_findings': len(findings)
        }
        
        # Load and render template
        try:
            template = self.jinja_env.get_template('report.html')
            html_content = template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render HTML template: {e}")
            raise
        
        # Determine output file
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = REPORT_DIR / f"scan_report_{timestamp}.html"
        
        # Write report
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to: {output_file}")
        return output_file
    
    def generate_json_report(
        self,
        findings: List[Finding],
        target_url: str,
        output_file: Path = None
    ) -> Path:
        """
        Generate JSON report for machine-readable output.
        
        Args:
            findings: List of vulnerability findings
            target_url: Target URL that was scanned
            output_file: Output file path (auto-generated if None)
            
        Returns:
            Path to generated JSON report
        """
        logger.info("Generating JSON report...")
        
        # Calculate statistics
        stats = self._calculate_statistics(findings)
        
        # Convert findings to dictionaries
        findings_data = []
        for f in findings:
            findings_data.append({
                'type': f.vuln_type,
                'url': f.url,
                'parameter': f.parameter,
                'payload': f.payload,
                'evidence': f.evidence,
                'severity': f.severity,
                'method': f.method,
                'description': f.description
            })
        
        # Build report structure
        report = {
            'scan_info': {
                'target_url': target_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '1.0'
            },
            'statistics': stats,
            'findings': findings_data
        }
        
        # Determine output file
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = REPORT_DIR / f"scan_report_{timestamp}.json"
        
        # Write report
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to: {output_file}")
        return output_file
    
    def generate_reports(
        self,
        findings: List[Finding],
        target_url: str,
        formats: List[str] = None
    ) -> Dict[str, Path]:
        """
        Generate reports in multiple formats.
        
        Args:
            findings: List of vulnerability findings
            target_url: Target URL that was scanned
            formats: List of formats to generate ('html', 'json', 'console')
            
        Returns:
            Dictionary mapping format to output file path
        """
        if formats is None:
            formats = ['console']
        
        output_files = {}
        
        # Always show console summary
        if 'console' in formats or not formats:
            self.generate_console_report(findings, target_url)
        
        # Generate HTML report
        if 'html' in formats or 'both' in formats:
            html_file = self.generate_html_report(findings, target_url)
            output_files['html'] = html_file
        
        # Generate JSON report
        if 'json' in formats or 'both' in formats:
            json_file = self.generate_json_report(findings, target_url)
            output_files['json'] = json_file
        
        return output_files
