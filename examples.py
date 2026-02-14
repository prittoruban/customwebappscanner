#!/usr/bin/env python3
"""
Programmatic Usage Examples — WebVulnScanner v2.0

Demonstrates how to use the scanner components from Python code
instead of the CLI. Run with: python3 examples.py

Educational purposes only.
"""

import sys
import os

# Ensure scanner/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))


# ─────────────────────────────────────────────────────
# Example 1 — Full Scan Pipeline (mirrors the CLI)
# ─────────────────────────────────────────────────────
def example_full_scan():
    """Run a complete scan: crawl → detect → report."""
    from utils.http import HTTPClient
    from crawler.crawler import WebCrawler
    from engine.executor import ScanExecutor
    from reporter.report import ReportGenerator

    target = 'http://testphp.vulnweb.com'   # Acunetix demo site

    # 1. Create an HTTP client (shared across all components)
    client = HTTPClient(
        timeout=10,
        max_retries=2,
        request_delay=0.1,
        verify_ssl=False,
    )

    # 2. Crawl the target for forms and URLs
    crawler = WebCrawler(
        start_url=target,
        max_depth=2,
        http_client=client,
    )
    forms = crawler.crawl()
    crawled_urls = list(crawler.visited_urls)
    print(f'[*] Crawled {len(crawled_urls)} URLs, found {len(forms)} forms')

    # 3. Execute scans (enable whichever you need)
    executor = ScanExecutor(http_client=client, max_workers=5)
    findings = executor.execute_scan(
        forms=forms,
        crawled_urls=crawled_urls,
        enable_xss=True,
        enable_sqli=True,
        enable_csrf=True,
        enable_headers=True,
        framework='python_flask',    # remediation framework
    )
    print(f'[*] Found {len(findings)} vulnerabilities')

    # 4. Generate reports
    reporter = ReportGenerator()
    output = reporter.generate_reports(
        findings=findings,
        target_url=target,
        formats=['console', 'html', 'json'],
    )
    for fmt, path in output.items():
        print(f'    {fmt}: {path}')

    client.close()


# ─────────────────────────────────────────────────────
# Example 2 — Single Scanner (XSS only, no crawl)
# ─────────────────────────────────────────────────────
def example_single_scanner():
    """Use a single scanner directly against a known form."""
    from utils.http import HTTPClient
    from scanner.xss import XSSScanner
    from crawler.crawler import Form, FormField

    client = HTTPClient(timeout=10, verify_ssl=False)

    # Construct a form manually (useful for targeted testing)
    form = Form(
        action='http://testphp.vulnweb.com/search.php',
        method='GET',
        fields=[FormField(name='test', field_type='text')],
        url='http://testphp.vulnweb.com',
    )

    scanner = XSSScanner(http_client=client)
    findings = scanner.scan_form(form)

    for f in findings:
        print(f'[{f.severity}] {f.vuln_type} in {f.parameter}: {f.payload}')

    client.close()


# ─────────────────────────────────────────────────────
# Example 3 — All 8 Scanner Types
# ─────────────────────────────────────────────────────
def example_all_scanners():
    """Enable every scanner type for comprehensive coverage."""
    from utils.http import HTTPClient
    from crawler.crawler import WebCrawler
    from engine.executor import ScanExecutor

    target = 'http://testphp.vulnweb.com'
    client = HTTPClient(timeout=10, verify_ssl=False)

    crawler = WebCrawler(start_url=target, max_depth=1, http_client=client)
    forms = crawler.crawl()
    crawled_urls = list(crawler.visited_urls)

    executor = ScanExecutor(http_client=client, max_workers=5)
    findings = executor.execute_scan(
        forms=forms,
        crawled_urls=crawled_urls,
        enable_xss=True,
        enable_sqli=True,
        enable_csrf=True,
        enable_ssrf=True,
        enable_lfi=True,
        enable_cmdi=True,
        enable_redirect=True,
        enable_headers=True,
        framework='python_django',    # Django-specific remediation
    )

    # Group findings by type
    by_type = {}
    for f in findings:
        by_type.setdefault(f.vuln_type, []).append(f)

    print(f'\n[*] {len(findings)} total findings:')
    for vuln_type, items in by_type.items():
        print(f'    {vuln_type}: {len(items)}')

    client.close()


# ─────────────────────────────────────────────────────
# Example 4 — Chain Detection
# ─────────────────────────────────────────────────────
def example_chain_detection():
    """Detect vulnerability chains from existing findings."""
    from engine.chain_detector import VulnChainDetector
    from models.finding import Finding

    # Simulate findings that form a chain (XSS + CSRF = session hijack)
    findings = [
        Finding(
            vuln_type='Cross-Site Scripting',
            url='http://example.com/profile',
            parameter='name',
            payload='<script>alert(1)</script>',
            evidence='reflected script tag',
            severity='HIGH',
            method='POST',
        ),
        Finding(
            vuln_type='CSRF',
            url='http://example.com/profile',
            parameter='',
            payload='',
            evidence='Missing CSRF token',
            severity='MEDIUM',
            method='POST',
        ),
    ]

    detector = VulnChainDetector()
    enriched = detector.detect_chains(findings)

    for f in enriched:
        if f.chain_id:
            print(f'[CHAIN {f.chain_id}] {f.vuln_type} — {f.url}')


# ─────────────────────────────────────────────────────
# Example 5 — Remediation Generation
# ─────────────────────────────────────────────────────
def example_remediation():
    """Get framework-specific remediation code for a finding."""
    from engine.remediation import RemediationGenerator
    from models.finding import Finding

    finding = Finding(
        vuln_type='SQL Injection',
        url='http://example.com/login',
        parameter='username',
        payload="' OR 1=1 --",
        evidence='MySQL error in response',
        severity='CRITICAL',
        method='POST',
    )

    gen = RemediationGenerator()

    # Single finding — get remediation for multiple frameworks
    for fw in ['python_flask', 'python_django', 'node_express', 'java_spring']:
        result = gen.get_remediation(finding, framework=fw)
        print(f'\n[{fw}] {result["title"]}')
        print(result['code'][:120] + '...')

    # Batch — enrich all findings in-place
    findings = [finding]
    gen.enrich_findings(findings, framework='python_flask')
    print(f'\nRemediation attached: {findings[0].remediation[:80]}...')


# ─────────────────────────────────────────────────────
# Example 6 — Custom HTTP Client Configuration
# ─────────────────────────────────────────────────────
def example_custom_http():
    """Configure the HTTP client for authenticated scanning."""
    from utils.http import HTTPClient

    # Authenticated scan with custom headers and cookies
    client = HTTPClient(
        timeout=15,
        max_retries=3,
        user_agent='CustomScanner/2.0',
        request_delay=0.5,          # be polite
        verify_ssl=True,
        cookies={'session': 'abc123', 'csrf': 'token456'},
        headers={'Authorization': 'Bearer eyJ...'},
    )

    # Use this client with any component
    response = client.get('http://httpbin.org/get')
    if response:
        print(f'Status: {response.status_code}')
        print(f'Headers sent: {response.request.headers.get("User-Agent")}')

    client.close()


# ─────────────────────────────────────────────────────
# Example 7 — JSON Report for CI/CD Integration
# ─────────────────────────────────────────────────────
def example_json_report():
    """Generate only a JSON report (useful for CI pipelines)."""
    from models.finding import Finding
    from reporter.report import ReportGenerator

    # Simulated findings (in real usage, these come from execute_scan)
    findings = [
        Finding(
            vuln_type='Security Headers',
            url='http://example.com',
            parameter='X-Frame-Options',
            payload='',
            evidence='Header missing',
            severity='MEDIUM',
            method='GET',
            description='X-Frame-Options header not set',
            cwe_id='CWE-1021',
            owasp_category='A05:2021',
        ),
    ]

    reporter = ReportGenerator()
    output = reporter.generate_reports(
        findings=findings,
        target_url='http://example.com',
        formats=['json'],                   # JSON only — no console noise
    )
    print(f'JSON report: {output.get("json", "N/A")}')


# ─────────────────────────────────────────────────────
# Example 8 — Finding Model and ScanResult
# ─────────────────────────────────────────────────────
def example_data_models():
    """Work with the Finding and ScanResult data models directly."""
    from models.finding import Finding, ScanResult, SeverityLevel

    # Create findings
    f1 = Finding(
        vuln_type='Cross-Site Scripting',
        url='http://example.com/search',
        parameter='q',
        payload='<img onerror=alert(1) src=x>',
        evidence='Reflected in response',
        severity='HIGH',
        method='GET',
        confidence='HIGH',
        cwe_id='CWE-79',
        owasp_category='A03:2021',
        scanner_module='XSS',
        tags=['reflected', 'event-handler'],
    )

    f2 = Finding(
        vuln_type='SQL Injection',
        url='http://example.com/login',
        parameter='user',
        payload="1' AND 1=1--",
        evidence='Boolean difference detected',
        severity='CRITICAL',
        method='POST',
    )

    # ScanResult aggregation
    result = ScanResult(
        target_url='http://example.com',
        findings=[f1, f2],
    )

    print(f'Target: {result.target_url}')
    print(f'Total findings: {result.total_findings}')
    print(f'Critical: {result.critical_count}')
    print(f'High: {result.high_count}')
    print(f'Risk score: {result.risk_score}/100')

    # Severity enum
    for level in SeverityLevel:
        print(f'  {level.name} = {level.value}')


# ─────────────────────────────────────────────────────
# Run all examples
# ─────────────────────────────────────────────────────
if __name__ == '__main__':
    examples = {
        '1': ('Full scan pipeline',          example_full_scan),
        '2': ('Single scanner (XSS)',        example_single_scanner),
        '3': ('All 8 scanner types',         example_all_scanners),
        '4': ('Chain detection',             example_chain_detection),
        '5': ('Remediation generation',      example_remediation),
        '6': ('Custom HTTP client',          example_custom_http),
        '7': ('JSON report for CI/CD',       example_json_report),
        '8': ('Data models',                 example_data_models),
    }

    print('WebVulnScanner v2.0 — Usage Examples')
    print('=' * 40)

    if len(sys.argv) > 1:
        choice = sys.argv[1]
        if choice in examples:
            name, fn = examples[choice]
            print(f'\n>>> Example {choice}: {name}\n')
            fn()
        else:
            print(f'Unknown example: {choice}. Choose 1-{len(examples)}.')
    else:
        print('\nUsage: python3 examples.py <number>')
        print('\nAvailable examples:')
        for num, (name, _) in examples.items():
            print(f'  {num}. {name}')
        print(f'\nExamples 4, 5, 7, 8 run offline (no network).')
        print(f'Examples 1, 2, 3, 6 make HTTP requests to demo targets.')
