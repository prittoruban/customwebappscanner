"""
Multi-threaded scan execution engine.

Coordinates vulnerability scanning across multiple forms and URLs using
thread pools. Integrates all scanner modules, vulnerability chain detection,
and auto-remediation enrichment.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import threading

from crawler.crawler import Form
from models.finding import Finding
from scanner.xss import XSSScanner
from scanner.sqli import SQLiScanner
from scanner.csrf import CSRFScanner
from scanner.headers import HeadersScanner
from scanner.ssrf import SSRFScanner
from scanner.redirect import RedirectScanner
from scanner.lfi import LFIScanner
from scanner.cmdi import CommandInjectionScanner
from engine.chain_detector import VulnChainDetector
from engine.remediation import RemediationGenerator
from utils.http import HTTPClient
from utils.logger import get_logger
from config import (
    DEFAULT_THREADS, MAX_THREADS, PAYLOAD_DIR,
    XSS_PAYLOAD_FILE, SQLI_PAYLOAD_FILE, SSRF_PAYLOAD_FILE,
    LFI_PAYLOAD_FILE, CMDI_PAYLOAD_FILE, REDIRECT_PAYLOAD_FILE,
)
from pathlib import Path

logger = get_logger(__name__)


class ScanExecutor:
    """
    Multi-threaded vulnerability scan executor.

    Supports 8 scan types:
    - XSS (Cross-Site Scripting) - context-aware with canary probing
    - SQLi (SQL Injection) - differential response analysis
    - CSRF (Cross-Site Request Forgery) - token entropy analysis
    - SSRF (Server-Side Request Forgery)
    - LFI (Local File Inclusion / Path Traversal)
    - Command Injection / RCE
    - Open Redirect
    - Security Headers & Cookie analysis (passive)

    Post-scan enrichment:
    - Vulnerability chain detection (finds compound attack paths)
    - Auto-remediation code generation (multi-framework)
    """

    def __init__(
        self,
        http_client: HTTPClient,
        max_workers: int = DEFAULT_THREADS
    ):
        self.http_client = http_client
        self.max_workers = min(max_workers, MAX_THREADS)

        # Thread-safe result storage
        self.results_lock = threading.Lock()
        self.all_findings: List[Finding] = []

        # Post-scan processors
        self.chain_detector = VulnChainDetector()
        self.remediation_gen = RemediationGenerator()

        logger.info(f"Scan executor initialized with {self.max_workers} threads")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _scan_form_with_scanner(
        self,
        form: Form,
        scanner: Any,
        scan_type: str
    ) -> List[Finding]:
        """Scan a single form with a specific scanner (thread-safe)."""
        try:
            findings = scanner.scan_form(form)
            if findings:
                logger.info(
                    f"{scan_type} scan on {form.action}: "
                    f"{len(findings)} vulnerabilities"
                )
            return findings
        except Exception as e:
            logger.error(f"Error in {scan_type} scan of {form.action}: {e}")
            return []

    def _scan_url_with_scanner(
        self,
        url: str,
        scanner: Any,
        scan_type: str
    ) -> List[Finding]:
        """Scan a URL with a passive scanner (e.g., headers)."""
        try:
            findings = scanner.scan_url(url)
            if findings:
                logger.info(
                    f"{scan_type} scan on {url}: "
                    f"{len(findings)} findings"
                )
            return findings
        except Exception as e:
            logger.error(f"Error in {scan_type} scan of {url}: {e}")
            return []

    def _add_findings(self, findings: List[Finding]):
        """Thread-safe finding collection."""
        with self.results_lock:
            self.all_findings.extend(findings)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def execute_scan(
        self,
        forms: List[Form],
        crawled_urls: List[str] = None,
        enable_xss: bool = False,
        enable_sqli: bool = False,
        enable_csrf: bool = False,
        enable_ssrf: bool = False,
        enable_lfi: bool = False,
        enable_cmdi: bool = False,
        enable_redirect: bool = False,
        enable_headers: bool = False,
        payload_dir: str = None,
        framework: str = "python_flask"
    ) -> List[Finding]:
        """
        Execute vulnerability scans on forms and URLs in parallel.

        Args:
            forms: Discovered forms to scan
            crawled_urls: URLs visited during crawl (for passive scans)
            enable_*: Toggle individual scan modules
            payload_dir: Custom payload directory override
            framework: Target framework for remediation code

        Returns:
            Enriched list of all findings (with chains + remediation)
        """
        active_flags = [
            enable_xss, enable_sqli, enable_csrf, enable_ssrf,
            enable_lfi, enable_cmdi, enable_redirect, enable_headers
        ]
        if not any(active_flags):
            logger.warning("No scan types enabled. Nothing to do.")
            return []

        if not forms and not crawled_urls:
            logger.warning("No forms or URLs to scan.")
            return []

        # Reset
        self.all_findings = []

        # Resolve payload file paths per scanner.
        # If a custom directory is given, build file paths from it;
        # otherwise pass None so each scanner uses its own default.
        p_base = Path(payload_dir) if payload_dir else None

        def _pf(filename: str):
            return p_base / filename if p_base else None

        # ---- Initialize enabled scanners ----
        form_scanners: List[tuple] = []  # (name, scanner_instance)

        if enable_xss:
            form_scanners.append(("XSS", XSSScanner(self.http_client, _pf(XSS_PAYLOAD_FILE))))
        if enable_sqli:
            form_scanners.append(("SQLi", SQLiScanner(self.http_client, _pf(SQLI_PAYLOAD_FILE))))
        if enable_csrf:
            form_scanners.append(("CSRF", CSRFScanner(self.http_client)))
        if enable_ssrf:
            form_scanners.append(("SSRF", SSRFScanner(self.http_client, _pf(SSRF_PAYLOAD_FILE))))
        if enable_lfi:
            form_scanners.append(("LFI", LFIScanner(self.http_client, _pf(LFI_PAYLOAD_FILE))))
        if enable_cmdi:
            form_scanners.append(("Command Injection", CommandInjectionScanner(self.http_client, _pf(CMDI_PAYLOAD_FILE))))
        if enable_redirect:
            form_scanners.append(("Open Redirect", RedirectScanner(self.http_client, _pf(REDIRECT_PAYLOAD_FILE))))

        url_scanners: List[tuple] = []
        if enable_headers:
            url_scanners.append(("Security Headers", HeadersScanner(self.http_client)))

        total_form_tasks = len(forms) * len(form_scanners) if forms else 0
        total_url_tasks = len(crawled_urls or []) * len(url_scanners)
        total_tasks = total_form_tasks + total_url_tasks

        logger.info(
            f"Starting scan: {len(forms or [])} forms x {len(form_scanners)} scanners "
            f"+ {len(crawled_urls or [])} URLs x {len(url_scanners)} scanners "
            f"= {total_tasks} tasks"
        )

        # ---- Execute in parallel ----
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {}

            # Submit form scan tasks
            for form in (forms or []):
                for scan_type, scanner in form_scanners:
                    fut = pool.submit(
                        self._scan_form_with_scanner, form, scanner, scan_type
                    )
                    future_map[fut] = (scan_type, getattr(form, 'action', '?'))

            # Submit URL (passive) scan tasks
            for url in (crawled_urls or []):
                for scan_type, scanner in url_scanners:
                    fut = pool.submit(
                        self._scan_url_with_scanner, url, scanner, scan_type
                    )
                    future_map[fut] = (scan_type, url)

            # Collect results
            completed = 0
            for future in as_completed(future_map):
                scan_type, target = future_map[future]
                completed += 1
                try:
                    findings = future.result()
                    self._add_findings(findings)
                    if completed % 10 == 0 or completed == len(future_map):
                        logger.debug(f"Progress: {completed}/{len(future_map)} tasks")
                except Exception as e:
                    logger.error(f"Task failed ({scan_type} on {target}): {e}")

        # ---- Post-scan enrichment ----
        logger.info("Running vulnerability chain detection...")
        chains = self.chain_detector.detect_chains(self.all_findings)
        if chains:
            logger.info(f"Detected {len(chains)} vulnerability chain(s)")

        logger.info("Generating remediation guidance...")
        self.remediation_gen.enrich_findings(self.all_findings, framework)

        logger.info(
            f"Scan complete. {len(self.all_findings)} total findings "
            f"({len(chains)} chains detected)"
        )
        return self.all_findings

    def execute_scan_sequential(
        self,
        forms: List[Form],
        crawled_urls: List[str] = None,
        enable_xss: bool = False,
        enable_sqli: bool = False,
        enable_csrf: bool = False,
        enable_ssrf: bool = False,
        enable_lfi: bool = False,
        enable_cmdi: bool = False,
        enable_redirect: bool = False,
        enable_headers: bool = False,
        payload_dir: str = None,
        framework: str = "python_flask"
    ) -> List[Finding]:
        """Sequential (single-threaded) scan for debugging."""
        active_flags = [
            enable_xss, enable_sqli, enable_csrf, enable_ssrf,
            enable_lfi, enable_cmdi, enable_redirect, enable_headers
        ]
        if not any(active_flags):
            return []

        self.all_findings = []
        p_dir = payload_dir or str(PAYLOAD_DIR)

        if enable_xss and forms:
            s = XSSScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "XSS"))
        if enable_sqli and forms:
            s = SQLiScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "SQLi"))
        if enable_csrf and forms:
            s = CSRFScanner(self.http_client)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "CSRF"))
        if enable_ssrf and forms:
            s = SSRFScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "SSRF"))
        if enable_lfi and forms:
            s = LFIScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "LFI"))
        if enable_cmdi and forms:
            s = CommandInjectionScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "RCE"))
        if enable_redirect and forms:
            s = RedirectScanner(self.http_client, p_dir)
            for form in forms:
                self.all_findings.extend(self._scan_form_with_scanner(form, s, "Redirect"))
        if enable_headers and crawled_urls:
            s = HeadersScanner(self.http_client)
            for url in crawled_urls:
                self.all_findings.extend(self._scan_url_with_scanner(url, s, "Headers"))

        # Post-scan enrichment
        self.chain_detector.detect_chains(self.all_findings)
        self.remediation_gen.enrich_findings(self.all_findings, framework)

        return self.all_findings
