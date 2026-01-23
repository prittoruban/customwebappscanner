"""
Multi-threaded scan execution engine.

Coordinates vulnerability scanning across multiple forms using thread pools.
Ensures thread-safe result collection and efficient resource utilization.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable
import threading

from crawler.crawler import Form
from scanner.xss import XSSScanner, Finding
from scanner.sqli import SQLiScanner
from scanner.csrf import CSRFScanner
from utils.http import HTTPClient
from utils.logger import get_logger
from config import DEFAULT_THREADS, MAX_THREADS

logger = get_logger(__name__)


class ScanExecutor:
    """
    Multi-threaded vulnerability scan executor.
    
    Features:
    - Thread-safe result collection
    - Parallel form scanning
    - Configurable thread pool size
    - Progress tracking
    """
    
    def __init__(
        self,
        http_client: HTTPClient,
        max_workers: int = DEFAULT_THREADS
    ):
        """
        Initialize scan executor.
        
        Args:
            http_client: HTTP client for scanners to use
            max_workers: Maximum number of concurrent threads
        """
        self.http_client = http_client
        self.max_workers = min(max_workers, MAX_THREADS)
        
        # Thread-safe result storage
        self.results_lock = threading.Lock()
        self.all_findings: List[Finding] = []
        
        logger.info(f"Scan executor initialized with {self.max_workers} threads")
    
    def _scan_form_with_scanner(
        self,
        form: Form,
        scanner: Any,
        scan_type: str
    ) -> List[Finding]:
        """
        Scan a single form with a specific scanner.
        
        Args:
            form: Form to scan
            scanner: Scanner instance (XSSScanner, SQLiScanner, or CSRFScanner)
            scan_type: Type of scan for logging (XSS, SQLi, CSRF)
            
        Returns:
            List of findings from this scan
        """
        try:
            findings = scanner.scan_form(form)
            
            if findings:
                logger.info(f"{scan_type} scan on {form.action}: {len(findings)} vulnerabilities")
            
            return findings
        
        except Exception as e:
            logger.error(f"Error in {scan_type} scan of {form.action}: {e}")
            return []
    
    def _add_findings(self, findings: List[Finding]):
        """
        Add findings to results in thread-safe manner.
        
        Args:
            findings: List of findings to add
        """
        with self.results_lock:
            self.all_findings.extend(findings)
    
    def execute_scan(
        self,
        forms: List[Form],
        enable_xss: bool = False,
        enable_sqli: bool = False,
        enable_csrf: bool = False,
        payload_dir: str = None
    ) -> List[Finding]:
        """
        Execute vulnerability scans on multiple forms in parallel.
        
        Args:
            forms: List of forms to scan
            enable_xss: Enable XSS scanning
            enable_sqli: Enable SQLi scanning
            enable_csrf: Enable CSRF scanning
            payload_dir: Optional custom payload directory
            
        Returns:
            List of all findings from all scans
        """
        if not any([enable_xss, enable_sqli, enable_csrf]):
            logger.warning("No scan types enabled. Nothing to do.")
            return []
        
        if not forms:
            logger.warning("No forms to scan.")
            return []
        
        # Reset results
        self.all_findings = []
        
        # Initialize enabled scanners
        scanners = []
        
        if enable_xss:
            xss_scanner = XSSScanner(self.http_client, payload_dir)
            scanners.append(('XSS', xss_scanner))
        
        if enable_sqli:
            sqli_scanner = SQLiScanner(self.http_client, payload_dir)
            scanners.append(('SQLi', sqli_scanner))
        
        if enable_csrf:
            csrf_scanner = CSRFScanner(self.http_client)
            scanners.append(('CSRF', csrf_scanner))
        
        logger.info(f"Starting scan of {len(forms)} forms with {len(scanners)} scanner(s)")
        
        # Create tasks: each form × each enabled scanner
        tasks = []
        for form in forms:
            for scan_type, scanner in scanners:
                tasks.append((form, scanner, scan_type))
        
        logger.info(f"Total scan tasks: {len(tasks)}")
        
        # Execute scans in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(
                    self._scan_form_with_scanner,
                    form,
                    scanner,
                    scan_type
                ): (form, scan_type)
                for form, scanner, scan_type in tasks
            }
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_task):
                form, scan_type = future_to_task[future]
                completed += 1
                
                try:
                    findings = future.result()
                    self._add_findings(findings)
                    
                    # Log progress
                    logger.debug(f"Progress: {completed}/{len(tasks)} tasks completed")
                
                except Exception as e:
                    logger.error(f"Task failed for {scan_type} on {form.action}: {e}")
        
        logger.info(f"Scan execution complete. Total findings: {len(self.all_findings)}")
        return self.all_findings
    
    def execute_scan_sequential(
        self,
        forms: List[Form],
        enable_xss: bool = False,
        enable_sqli: bool = False,
        enable_csrf: bool = False,
        payload_dir: str = None
    ) -> List[Finding]:
        """
        Execute vulnerability scans sequentially (single-threaded).
        
        Useful for debugging or when thread safety is a concern.
        
        Args:
            forms: List of forms to scan
            enable_xss: Enable XSS scanning
            enable_sqli: Enable SQLi scanning
            enable_csrf: Enable CSRF scanning
            payload_dir: Optional custom payload directory
            
        Returns:
            List of all findings
        """
        all_findings = []
        
        # Initialize enabled scanners
        if enable_xss:
            xss_scanner = XSSScanner(self.http_client, payload_dir)
            findings = xss_scanner.scan(forms)
            all_findings.extend(findings)
        
        if enable_sqli:
            sqli_scanner = SQLiScanner(self.http_client, payload_dir)
            findings = sqli_scanner.scan(forms)
            all_findings.extend(findings)
        
        if enable_csrf:
            csrf_scanner = CSRFScanner(self.http_client)
            findings = csrf_scanner.scan(forms)
            all_findings.extend(findings)
        
        return all_findings
