#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner v2.0 — CLI Entry Point

Production-grade educational tool for detecting web vulnerabilities:
  XSS | SQLi | CSRF | SSRF | LFI | RCE | Open Redirect | Security Headers

Features unique to this scanner:
  • Context-aware XSS detection with canary probing
  • Differential response analysis for blind SQLi
  • Vulnerability chain detection (compound attack paths)
  • Auto-remediation code generation (Flask / Django / Express / PHP)

⚠️  IMPORTANT: For educational and authorized testing purposes only!
    Use only on applications you own or have explicit permission to test.

Usage:
    python main.py -u http://example.com --all
    python main.py -u http://example.com --xss --sqli --headers --report html
    python main.py -u http://example.com --all --framework python_django --report both
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


# ──────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────
def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner v2.0 (Educational)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for ALL vulnerability types
  python main.py -u http://testphp.vulnweb.com --all

  # Selective scan with HTML report
  python main.py -u http://example.com --xss --sqli --headers --report html

  # Full scan with Django remediation + JSON report
  python main.py -u http://example.com --all --framework python_django --report both

  # Deep crawl with custom threads
  python main.py -u http://example.com --all --depth 5 --threads 20

⚠️  WARNING: Use only on systems you own or have permission to test!
        """
    )

    # Required
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (required)'
    )

    # ---- Scan Types ----
    scan_group = parser.add_argument_group('Scan Types')
    scan_group.add_argument('--all', action='store_true',
                            help='Enable ALL scan types')
    scan_group.add_argument('--xss', action='store_true',
                            help='Cross-Site Scripting (XSS) — context-aware')
    scan_group.add_argument('--sqli', action='store_true',
                            help='SQL Injection — error/boolean-blind/time-based')
    scan_group.add_argument('--csrf', action='store_true',
                            help='Cross-Site Request Forgery')
    scan_group.add_argument('--ssrf', action='store_true',
                            help='Server-Side Request Forgery')
    scan_group.add_argument('--lfi', action='store_true',
                            help='Local File Inclusion / Path Traversal')
    scan_group.add_argument('--cmdi', action='store_true',
                            help='OS Command Injection / RCE')
    scan_group.add_argument('--redirect', action='store_true',
                            help='Open Redirect')
    scan_group.add_argument('--headers', action='store_true',
                            help='Security Headers & Cookie analysis (passive)')

    # ---- Crawler ----
    crawler_group = parser.add_argument_group('Crawler Options')
    crawler_group.add_argument(
        '--depth', type=int, default=config.DEFAULT_CRAWL_DEPTH,
        help=f'Maximum crawl depth (default: {config.DEFAULT_CRAWL_DEPTH})'
    )

    # ---- Scanner ----
    scanner_group = parser.add_argument_group('Scanner Options')
    scanner_group.add_argument(
        '--threads', type=int, default=config.DEFAULT_THREADS,
        help=f'Concurrent threads (default: {config.DEFAULT_THREADS})'
    )
    scanner_group.add_argument(
        '--payload-dir', type=str,
        help=f'Custom payload directory (default: {config.PAYLOAD_DIR})'
    )
    scanner_group.add_argument(
        '--framework',
        choices=['python_flask', 'python_django', 'javascript_express', 'php'],
        default='python_flask',
        help='Target framework for remediation code (default: python_flask)'
    )

    # ---- Report ----
    report_group = parser.add_argument_group('Report Options')
    report_group.add_argument(
        '--report',
        choices=config.REPORT_FORMATS,
        default='console',
        help='Report output format (default: console)'
    )

    # ---- Misc ----
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose/debug logging'
    )

    return parser.parse_args()


def validate_arguments(args):
    """Validate parsed arguments. Returns True if valid."""
    # --all expands all flags
    if args.all:
        args.xss = args.sqli = args.csrf = True
        args.ssrf = args.lfi = args.cmdi = True
        args.redirect = args.headers = True

    scan_flags = [
        args.xss, args.sqli, args.csrf, args.ssrf,
        args.lfi, args.cmdi, args.redirect, args.headers
    ]
    if not any(scan_flags):
        print("ERROR: Enable at least one scan type (--xss, --sqli, --all, …)")
        return False

    if not args.url.startswith(('http://', 'https://')):
        print("ERROR: URL must start with http:// or https://")
        return False

    if args.depth < 0 or args.depth > 10:
        print("ERROR: Crawl depth must be between 0 and 10")
        return False

    if args.threads < 1 or args.threads > config.MAX_THREADS:
        print(f"ERROR: Thread count must be between 1 and {config.MAX_THREADS}")
        return False

    return True


def print_banner():
    """Print ASCII art banner."""
    banner = r"""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   Web Application Vulnerability Scanner  v2.0                         ║
║                                                                       ║
║   XSS | SQLi | CSRF | SSRF | LFI | RCE | Redirect | Headers         ║
║   Chain Detection • Auto-Remediation • Context-Aware Analysis         ║
║                                                                       ║
║   WARNING: For authorized testing only!                               ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────
def main():
    """Main entry point for the vulnerability scanner."""
    args = parse_arguments()

    if not validate_arguments(args):
        sys.exit(1)

    logger = setup_logger(__name__, verbose=args.verbose)
    print_banner()

    # ---- Display configuration ----
    enabled = []
    for name, flag in [
        ('XSS', args.xss), ('SQLi', args.sqli), ('CSRF', args.csrf),
        ('SSRF', args.ssrf), ('LFI', args.lfi), ('RCE', args.cmdi),
        ('Redirect', args.redirect), ('Headers', args.headers),
    ]:
        if flag:
            enabled.append(name)

    print("\n[*] Scan Configuration:")
    print(f"    Target URL : {args.url}")
    print(f"    Crawl Depth: {args.depth}")
    print(f"    Threads    : {args.threads}")
    print(f"    Scan Types : {', '.join(enabled)}")
    print(f"    Framework  : {args.framework}")
    print(f"    Report     : {args.report}")
    print()

    try:
        # ---- Step 1: Crawl ----
        logger.info("Initializing HTTP client...")
        http_client = HTTPClient()

        logger.info(f"Starting crawl of {args.url}")
        print(f"[*] Crawling {args.url} ...")

        crawler = WebCrawler(
            start_url=args.url,
            max_depth=args.depth,
            http_client=http_client
        )
        forms = crawler.crawl()
        crawled_urls = list(crawler.visited_urls)

        if not forms and not args.headers:
            print("[!] No forms found during crawl. Nothing to scan.")
            logger.warning("No forms discovered. Exiting.")
            return

        print(
            f"[+] Crawl complete — {len(forms)} form(s) "
            f"across {len(crawled_urls)} page(s)"
        )
        print()

        # ---- Step 2: Scan ----
        logger.info("Initializing scan executor...")
        print(f"[*] Scanning with {args.threads} thread(s) ...")

        executor = ScanExecutor(
            http_client=http_client,
            max_workers=args.threads
        )

        findings = executor.execute_scan(
            forms=forms,
            crawled_urls=crawled_urls,
            enable_xss=args.xss,
            enable_sqli=args.sqli,
            enable_csrf=args.csrf,
            enable_ssrf=args.ssrf,
            enable_lfi=args.lfi,
            enable_cmdi=args.cmdi,
            enable_redirect=args.redirect,
            enable_headers=args.headers,
            payload_dir=args.payload_dir,
            framework=args.framework,
        )

        print(f"[+] Scan complete — {len(findings)} finding(s)")
        print()

        # ---- Step 3: Report ----
        logger.info("Generating reports...")
        print("[*] Generating report(s) ...")

        reporter = ReportGenerator()

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

        if output_files:
            print("\n[+] Report files generated:")
            for fmt, fpath in output_files.items():
                print(f"    {fmt.upper()}: {fpath}")

        print("\n[+] Done!")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        logger.info("Scan interrupted by user (Ctrl+C)")
        sys.exit(130)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        logger.exception("Unhandled exception in main")
        sys.exit(1)

    finally:
        try:
            http_client.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
