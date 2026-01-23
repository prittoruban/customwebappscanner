#!/usr/bin/env python3
"""
Example usage scenarios for the Web Application Vulnerability Scanner.

This script demonstrates various ways to use the scanner programmatically.
"""

import sys
from pathlib import Path

# Add scanner to path
sys.path.insert(0, str(Path(__file__).parent / 'scanner'))

from utils.logger import setup_logger
from utils.http import HTTPClient
from crawler.crawler import WebCrawler
from engine.executor import ScanExecutor
from reporter.report import ReportGenerator


def example_basic_scan():
    """
    Example 1: Basic XSS scan with minimal configuration.
    """
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic XSS Scan")
    print("="*70)
    
    # Setup
    logger = setup_logger(__name__, verbose=True)
    target_url = "http://testphp.vulnweb.com"
    
    # Initialize components
    http_client = HTTPClient()
    crawler = WebCrawler(target_url, max_depth=1, http_client=http_client)
    
    # Crawl
    print(f"Crawling {target_url}...")
    forms = crawler.crawl()
    print(f"Found {len(forms)} forms")
    
    # Scan
    print("Scanning for XSS...")
    executor = ScanExecutor(http_client, max_workers=5)
    findings = executor.execute_scan(
        forms=forms,
        enable_xss=True,
        enable_sqli=False,
        enable_csrf=False
    )
    
    # Report
    print(f"Found {len(findings)} vulnerabilities")
    reporter = ReportGenerator()
    reporter.generate_console_report(findings, target_url)
    
    http_client.close()


def example_full_scan_with_reports():
    """
    Example 2: Full scan with HTML and JSON reports.
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Full Scan with Reports")
    print("="*70)
    
    # Setup
    logger = setup_logger(__name__, verbose=False)
    target_url = "http://testphp.vulnweb.com"
    
    # Initialize
    http_client = HTTPClient()
    crawler = WebCrawler(target_url, max_depth=2, http_client=http_client)
    
    # Crawl
    print(f"Crawling {target_url}...")
    forms = crawler.crawl()
    
    if not forms:
        print("No forms found!")
        return
    
    # Scan with all modules
    print("Scanning for XSS, SQLi, and CSRF...")
    executor = ScanExecutor(http_client, max_workers=10)
    findings = executor.execute_scan(
        forms=forms,
        enable_xss=True,
        enable_sqli=True,
        enable_csrf=True
    )
    
    # Generate reports
    print(f"\nGenerating reports for {len(findings)} findings...")
    reporter = ReportGenerator()
    output_files = reporter.generate_reports(
        findings=findings,
        target_url=target_url,
        formats=['console', 'html', 'json']
    )
    
    print("\nReport files:")
    for format_type, file_path in output_files.items():
        print(f"  {format_type}: {file_path}")
    
    http_client.close()


def example_custom_payloads():
    """
    Example 3: Using custom payload directory.
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Custom Payload Directory")
    print("="*70)
    
    # You can create a custom payload directory with your own test vectors
    custom_payload_dir = Path(__file__).parent / "custom_payloads"
    
    print(f"Custom payload directory: {custom_payload_dir}")
    print("(Create xss.txt and sqli.txt in this directory)")
    
    # Then use it in scanning:
    # executor.execute_scan(..., payload_dir=custom_payload_dir)


def example_sequential_scan():
    """
    Example 4: Sequential (non-threaded) scanning for debugging.
    """
    print("\n" + "="*70)
    print("EXAMPLE 4: Sequential Scan (Single-threaded)")
    print("="*70)
    
    # Setup
    logger = setup_logger(__name__, verbose=True)
    target_url = "http://testphp.vulnweb.com"
    
    # Initialize
    http_client = HTTPClient()
    crawler = WebCrawler(target_url, max_depth=1, http_client=http_client)
    
    # Crawl
    forms = crawler.crawl()
    
    # Sequential scan (easier to debug)
    executor = ScanExecutor(http_client)
    findings = executor.execute_scan_sequential(
        forms=forms,
        enable_xss=True,
        enable_sqli=False,
        enable_csrf=False
    )
    
    print(f"Found {len(findings)} vulnerabilities")
    
    http_client.close()


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║   Web Application Vulnerability Scanner - Usage Examples         ║
╚═══════════════════════════════════════════════════════════════════╝

⚠️  These examples use test targets. Replace with your own authorized
   testing targets before running!
    """)
    
    # Run examples
    # Uncomment the example you want to run:
    
    # example_basic_scan()
    # example_full_scan_with_reports()
    # example_custom_payloads()
    # example_sequential_scan()
    
    print("\n✓ Examples complete. Edit this file to run specific examples.")
