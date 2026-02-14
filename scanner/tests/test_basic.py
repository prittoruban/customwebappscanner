"""
Comprehensive unit tests for Web Application Vulnerability Scanner v2.0.

Tests cover:
- All module imports
- Finding model & ScanResult properties
- Each scanner class instantiation
- VulnChainDetector chain detection
- RemediationGenerator enrichment
- ScanExecutor initialization
- ReportGenerator output
- Config values sanity
- Payload files existence
"""

import sys
import os
import unittest
import tempfile
import json
from pathlib import Path
from dataclasses import fields as dc_fields

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestImports(unittest.TestCase):
    """Verify every module can be imported."""

    def test_models_import(self):
        from models.finding import Finding, ScanResult, SeverityLevel
        self.assertTrue(callable(Finding))
        self.assertTrue(callable(ScanResult))

    def test_scanner_base_import(self):
        from scanner.base import BaseScanner
        self.assertTrue(callable(BaseScanner))

    def test_scanner_modules_import(self):
        from scanner.xss import XSSScanner
        from scanner.sqli import SQLiScanner
        from scanner.csrf import CSRFScanner
        from scanner.headers import HeadersScanner
        from scanner.ssrf import SSRFScanner
        from scanner.redirect import RedirectScanner
        from scanner.lfi import LFIScanner
        from scanner.cmdi import CommandInjectionScanner

    def test_engine_imports(self):
        from engine.chain_detector import VulnChainDetector
        from engine.remediation import RemediationGenerator
        from engine.executor import ScanExecutor

    def test_reporter_import(self):
        from reporter.report import ReportGenerator

    def test_utils_import(self):
        from utils.http import HTTPClient
        from utils.logger import get_logger

    def test_config_import(self):
        import config
        self.assertTrue(hasattr(config, 'PAYLOAD_DIR'))
        self.assertTrue(hasattr(config, 'MAX_THREADS'))


class TestFindingModel(unittest.TestCase):
    """Test the Finding dataclass."""

    def setUp(self):
        from models.finding import Finding
        self.Finding = Finding

    def test_create_finding(self):
        f = self.Finding(
            vuln_type='XSS', url='http://test.com', parameter='q',
            payload='<script>alert(1)</script>', evidence='reflected',
            severity='HIGH', method='GET', description='Reflected XSS found'
        )
        self.assertEqual(f.vuln_type, 'XSS')
        self.assertEqual(f.severity, 'HIGH')

    def test_finding_default_fields(self):
        f = self.Finding(
            vuln_type='SQLi', url='http://ex.com', parameter='id',
            payload="1' OR '1'='1", evidence='error', severity='CRITICAL',
            method='POST', description='SQLi detected'
        )
        self.assertFalse(f.remediation)  # empty string or None
        self.assertFalse(f.cwe_id)  # empty string or None
        self.assertFalse(f.chain_id)  # empty string or None

    def test_finding_has_all_expected_fields(self):
        field_names = {f.name for f in dc_fields(self.Finding)}
        expected = {
            'vuln_type', 'url', 'parameter', 'payload', 'evidence',
            'severity', 'method', 'description', 'remediation',
            'cwe_id', 'owasp_category', 'confidence', 'scanner_module',
            'context', 'chain_id', 'raw_request', 'raw_response', 'tags'
        }
        self.assertTrue(expected.issubset(field_names))


class TestScanResult(unittest.TestCase):
    def test_empty_scan_result(self):
        from models.finding import ScanResult
        sr = ScanResult(target_url='http://x.com', findings=[])
        self.assertEqual(sr.total_findings, 0)
        self.assertEqual(sr.risk_score, 0)

    def test_scan_result_counts(self):
        from models.finding import Finding, ScanResult
        findings = [
            Finding(vuln_type='XSS', url='u', parameter='p', payload='x',
                    evidence='e', severity='CRITICAL', method='GET', description='d'),
            Finding(vuln_type='XSS', url='u', parameter='p', payload='x',
                    evidence='e', severity='HIGH', method='GET', description='d'),
            Finding(vuln_type='SQLi', url='u', parameter='p', payload='x',
                    evidence='e', severity='MEDIUM', method='POST', description='d'),
        ]
        sr = ScanResult(target_url='http://x.com', findings=findings)
        self.assertEqual(sr.total_findings, 3)
        self.assertEqual(sr.critical_count, 1)
        self.assertEqual(sr.high_count, 1)
        self.assertTrue(sr.risk_score > 0)


class TestChainDetector(unittest.TestCase):
    def test_xss_csp_chain(self):
        from models.finding import Finding
        from engine.chain_detector import VulnChainDetector
        findings = [
            Finding(vuln_type='XSS', url='http://x.com/a', parameter='q',
                    payload='<script>', evidence='reflected', severity='HIGH',
                    method='GET', description='XSS'),
            Finding(vuln_type='Security Headers', url='http://x.com/a',
                    parameter='Content-Security-Policy', payload='',
                    evidence='missing CSP', severity='MEDIUM', method='GET',
                    description='Missing CSP header'),
        ]
        detector = VulnChainDetector()
        chains = detector.detect_chains(findings)
        self.assertGreaterEqual(len(chains), 1)

    def test_no_chains_single_finding(self):
        from models.finding import Finding
        from engine.chain_detector import VulnChainDetector
        findings = [
            Finding(vuln_type='LFI', url='http://x.com/a', parameter='file',
                    payload='../../etc/passwd', evidence='root:x:', severity='HIGH',
                    method='GET', description='LFI'),
        ]
        detector = VulnChainDetector()
        chains = detector.detect_chains(findings)
        self.assertEqual(len(chains), 0)


class TestRemediationGenerator(unittest.TestCase):
    def test_xss_flask_remediation(self):
        from models.finding import Finding
        from engine.remediation import RemediationGenerator
        f = Finding(vuln_type='XSS', url='http://x.com', parameter='q',
                    payload='<script>', evidence='e', severity='HIGH',
                    method='GET', description='d')
        gen = RemediationGenerator()
        gen.enrich_findings([f], 'python_flask')
        self.assertIn('Flask', f.remediation)

    def test_sqli_django_remediation(self):
        from models.finding import Finding
        from engine.remediation import RemediationGenerator
        f = Finding(vuln_type='SQLi', url='http://x.com', parameter='id',
                    payload="1'", evidence='error', severity='CRITICAL',
                    method='GET', description='d')
        gen = RemediationGenerator()
        gen.enrich_findings([f], 'python_django')
        self.assertIn('Django', f.remediation)

    def test_unknown_vuln_type(self):
        from models.finding import Finding
        from engine.remediation import RemediationGenerator
        f = Finding(vuln_type='UnknownType', url='http://x.com', parameter='p',
                    payload='x', evidence='e', severity='LOW',
                    method='GET', description='d')
        gen = RemediationGenerator()
        gen.enrich_findings([f], 'python_flask')
        self.assertIsNotNone(f.remediation)


class TestScannerInstantiation(unittest.TestCase):
    def _client(self):
        from utils.http import HTTPClient
        return HTTPClient()

    def test_xss_scanner(self):
        from scanner.xss import XSSScanner
        c = self._client()
        s = XSSScanner(c)
        self.assertEqual(s.scanner_name, 'XSS')
        c.close()

    def test_sqli_scanner(self):
        from scanner.sqli import SQLiScanner
        c = self._client()
        s = SQLiScanner(c)
        self.assertEqual(s.scanner_name, 'SQLi')
        c.close()

    def test_csrf_scanner(self):
        from scanner.csrf import CSRFScanner
        c = self._client()
        s = CSRFScanner(c)
        self.assertEqual(s.scanner_name, 'CSRF')
        c.close()

    def test_headers_scanner(self):
        from scanner.headers import HeadersScanner
        c = self._client()
        s = HeadersScanner(c)
        self.assertIsNotNone(s)
        c.close()

    def test_ssrf_scanner(self):
        from scanner.ssrf import SSRFScanner
        c = self._client()
        s = SSRFScanner(c)
        self.assertEqual(s.scanner_name, 'SSRF')
        c.close()

    def test_redirect_scanner(self):
        from scanner.redirect import RedirectScanner
        c = self._client()
        s = RedirectScanner(c)
        self.assertEqual(s.scanner_name, 'Open Redirect')
        c.close()

    def test_lfi_scanner(self):
        from scanner.lfi import LFIScanner
        c = self._client()
        s = LFIScanner(c)
        self.assertEqual(s.scanner_name, 'LFI')
        c.close()

    def test_cmdi_scanner(self):
        from scanner.cmdi import CommandInjectionScanner
        c = self._client()
        s = CommandInjectionScanner(c)
        self.assertEqual(s.scanner_name, 'Command Injection')
        c.close()


class TestExecutor(unittest.TestCase):
    def test_executor_init(self):
        from utils.http import HTTPClient
        from engine.executor import ScanExecutor
        c = HTTPClient()
        ex = ScanExecutor(c, max_workers=5)
        self.assertEqual(ex.max_workers, 5)
        c.close()

    def test_executor_no_scans(self):
        from utils.http import HTTPClient
        from engine.executor import ScanExecutor
        c = HTTPClient()
        ex = ScanExecutor(c)
        result = ex.execute_scan(forms=[], crawled_urls=[])
        self.assertEqual(result, [])
        c.close()


class TestReporter(unittest.TestCase):
    def test_console_report_empty(self):
        from reporter.report import ReportGenerator
        rg = ReportGenerator()
        rg.generate_console_report([], 'http://test.com')

    def test_json_report_structure(self):
        from models.finding import Finding
        from reporter.report import ReportGenerator
        findings = [
            Finding(vuln_type='XSS', url='http://test.com', parameter='q',
                    payload='<script>', evidence='reflected', severity='HIGH',
                    method='GET', description='XSS', cwe_id='79',
                    owasp_category='A03:2021', confidence='high'),
        ]
        rg = ReportGenerator()
        with tempfile.TemporaryDirectory() as tmp:
            out = rg.generate_json_report(findings, 'http://test.com',
                                          Path(tmp) / 'report.json')
            self.assertTrue(out.exists())
            data = json.loads(out.read_text())
            self.assertIn('findings', data)
            self.assertEqual(len(data['findings']), 1)
            self.assertEqual(data['findings'][0]['cwe_id'], '79')
            self.assertEqual(data['scan_info']['scanner_version'], '2.0')


class TestConfig(unittest.TestCase):
    def test_payload_dir_exists(self):
        import config
        self.assertTrue(config.PAYLOAD_DIR.is_dir())

    def test_security_headers(self):
        import config
        self.assertIn('Content-Security-Policy', config.SECURITY_HEADERS)
        self.assertIn('X-Content-Type-Options', config.SECURITY_HEADERS)

    def test_cwe_mappings(self):
        import config
        self.assertIn('79', config.CWE_MAPPINGS.get('XSS', ''))
        self.assertIn('89', config.CWE_MAPPINGS.get('SQLi', ''))
        self.assertIn('352', config.CWE_MAPPINGS.get('CSRF', ''))

    def test_thread_limits(self):
        import config
        self.assertGreater(config.MAX_THREADS, 0)
        self.assertLessEqual(config.DEFAULT_THREADS, config.MAX_THREADS)


class TestPayloadFiles(unittest.TestCase):
    def test_payload_files_exist(self):
        import config
        for name in ['xss.txt', 'sqli.txt', 'ssrf.txt', 'lfi.txt', 'cmdi.txt', 'redirect.txt']:
            path = config.PAYLOAD_DIR / name
            self.assertTrue(path.exists(), f"Missing: {name}")
            self.assertGreater(len(path.read_text().strip()), 50, f"Too small: {name}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
