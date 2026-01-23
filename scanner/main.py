#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner - CLI Entry Point

Educational demo tool for detecting XSS, SQLi, and CSRF vulnerabilities.

⚠️ IMPORTANT: For educational and authorized testing purposes only!
   - Use only on applications you own or have explicit permission to test
   - Do not use on production systems without authorization
   - This is a DEMO tool, not for malicious use

Usage:
    python main.py -u http://example.com --xss --sqli --csrf
    python main.py -u http://example.com --xss --threads 10 --report html
    python main.py -u http://example.com --sqli --csrf --depth 3 --report both
"""

import argparse
import sys
from pathlib import Path

# Ensure proper imports when run as script
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).parent))

import config
from utils.logger import setup_logger
from utils.http import HTTPClient
from crawler.crawler import WebCrawler
from engine.executor import ScanExecutor
from reporter.report import ReportGenerator


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        Namespace with parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner (Educational Demo)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for all vulnerabilities
  python main.py -u http://testphp.vulnweb.com --xss --sqli --csrf

  # XSS scan only with 10 threads
  python main.py -u http://example.com --xss --threads 10

  # Full scan with HTML report
  python main.py -u http://example.com --xss --sqli --csrf --report html

  # Deep crawl with JSON report
  python main.py -u http://example.com --xss --depth 5 --report json

⚠️  WARNING: Use only on systems you own or have permission to test!
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (required)'
    )
    
    # Scan type selection
    scan_group = parser.add_argument_group('Scan Types')
    scan_group.add_argument(
        '--xss',
        action='store_true',
        help='Enable Cross-Site Scripting (XSS) scan'
    )
    scan_group.add_argument(
        '--sqli',
        action='store_true',
        help='Enable SQL Injection (SQLi) scan'
    )
    scan_group.add_argument(
        '--csrf',
        action='store_true',
        help='Enable Cross-Site Request Forgery (CSRF) scan'
    )
    
    # Crawler options
    crawler_group = parser.add_argument_group('Crawler Options')
    crawler_group.add_argument(
        '--depth',
        type=int,
        default=config.DEFAULT_CRAWL_DEPTH,
        help=f'Maximum crawl depth (default: {config.DEFAULT_CRAWL_DEPTH})'
    )
    
    # Scanner options
    scanner_group = parser.add_argument_group('Scanner Options')
    scanner_group.add_argument(
        '--threads',
        type=int,
        default=config.DEFAULT_THREADS,
        help=f'Number of concurrent threads (default: {config.DEFAULT_THREADS})'
    )
    scanner_group.add_argument(
        '--payload-dir',
        type=str,
        help=f'Custom payload directory (default: {config.PAYLOAD_DIR})'
    )
    
    # Report options
    report_group = parser.add_argument_group('Report Options')
    report_group.add_argument(
        '--report',
        choices=config.REPORT_FORMATS,
        default='console',
        help='Report output format (default: console)'
    )
    
    # Logging options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose/debug logging'
    )
    
    return parser.parse_args()


def validate_arguments(args):
    """
    Validate parsed arguments.
    
    Args:
        args: Parsed arguments namespace
        
    Returns:
        True if valid, False otherwise
    """
    # Check if at least one scan type is enabled
    if not any([args.xss, args.sqli, args.csrf]):
        print("ERROR: At least one scan type must be enabled (--xss, --sqli, or --csrf)")
        return False
    
    # Validate URL format
    if not args.url.startswith(('http://', 'https://')):
        print("ERROR: URL must start with http:// or https://")
        return False
    
    # Validate depth
    if args.depth < 0 or args.depth > 10:
        print("ERROR: Crawl depth must be between 0 and 10")
        return False
    
    # Validate threads
    if args.threads < 1 or args.threads > 50:
        print("ERROR: Thread count must be between 1 and 50")
        return False
    
    return True


def print_banner():
    """Print ASCII art banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   🔒 Web Application Vulnerability Scanner v1.0                  ║
║                                                                   ║
║   Educational Demo Tool - XSS | SQLi | CSRF Detection            ║
║                                                                   ║
║   ⚠️  WARNING: For authorized testing only!                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point for the vulnerability scanner."""
    
    # Parse and validate arguments
    args = parse_arguments()
    
    if not validate_arguments(args):
        sys.exit(1)
    
    # Setup logging
    logger = setup_logger(__name__, verbose=args.verbose)
    
    # Print banner
    print_banner()
    
    # Display scan configuration
    print("\n📋 Scan Configuration:")
    print(f"   Target URL: {args.url}")
    print(f"   Crawl Depth: {args.depth}")
    print(f"   Threads: {args.threads}")
    print(f"   Scan Types: ", end="")
    
    enabled_scans = []
    if args.xss:
        enabled_scans.append("XSS")
    if args.sqli:
        enabled_scans.append("SQLi")
    if args.csrf:
        enabled_scans.append("CSRF")
    print(", ".join(enabled_scans))
    
    print(f"   Report Format: {args.report}")
    print()
    
    try:
        # Initialize HTTP client
        logger.info("Initializing HTTP client...")
        http_client = HTTPClient()
        
        # Step 1: Crawl target website
        logger.info(f"Starting crawl of {args.url}")
        print(f"🕷️  Crawling {args.url}...")
        
        crawler = WebCrawler(
            start_url=args.url,
            max_depth=args.depth,
            http_client=http_client
        )
        
        forms = crawler.crawl()
        
        if not forms:
            print("⚠️  No forms found during crawl. Nothing to scan.")
            logger.warning("No forms discovered. Exiting.")
            return
        
        print(f"✓ Crawl complete. Found {len(forms)} form(s) across {len(crawler.visited_urls)} page(s)")
        print()
        
        # Step 2: Execute vulnerability scans
        logger.info("Initializing scan executor...")
        print(f"🔍 Starting vulnerability scan with {args.threads} thread(s)...")
        
        executor = ScanExecutor(
            http_client=http_client,
            max_workers=args.threads
        )
        
        findings = executor.execute_scan(
            forms=forms,
            enable_xss=args.xss,
            enable_sqli=args.sqli,
            enable_csrf=args.csrf,
            payload_dir=args.payload_dir
        )
        
        print(f"✓ Scan complete. Found {len(findings)} vulnerability/vulnerabilities")
        print()
        
        # Step 3: Generate reports
        logger.info("Generating reports...")
        print("📊 Generating report(s)...")
        
        reporter = ReportGenerator()
        
        # Determine report formats
        report_formats = []
        if args.report == 'both':
            report_formats = ['console', 'html', 'json']
        elif args.report == 'console':
            report_formats = ['console']
        else:
            report_formats = ['console', args.report]
        
        output_files = reporter.generate_reports(
            findings=findings,
            target_url=args.url,
            formats=report_formats
        )
        
        # Display output file locations
        if output_files:
            print("\n📁 Report files generated:")
            for format_type, file_path in output_files.items():
                print(f"   {format_type.upper()}: {file_path}")
        
        print("\n✓ Scan complete!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        logger.info("Scan interrupted by user (Ctrl+C)")
        sys.exit(130)
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Unhandled exception in main")
        sys.exit(1)
    
    finally:
        # Cleanup
        try:
            http_client.close()
        except:
            pass


if __name__ == '__main__':
    main()
