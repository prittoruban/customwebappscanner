#!/usr/bin/env python3
"""
Basic functionality test for the vulnerability scanner.

Tests core components without making external HTTP requests.
"""

import sys
from pathlib import Path

# Add scanner to path
sys.path.insert(0, str(Path(__file__).parent / 'scanner'))

from crawler.crawler import Form, FormField
from scanner.xss import Finding
from utils.logger import setup_logger


def test_form_creation():
    """Test creating Form objects"""
    print("\n1. Testing Form creation...")
    
    form = Form(
        action="http://example.com/submit",
        method="POST",
        fields=[
            FormField(name="username", field_type="text"),
            FormField(name="password", field_type="password"),
        ],
        url="http://example.com"
    )
    
    assert form.action == "http://example.com/submit"
    assert form.method == "POST"
    assert len(form.fields) == 2
    assert form.get_field_names() == ["username", "password"]
    
    print("   ✓ Form object creation works")
    return True


def test_finding_creation():
    """Test creating Finding objects"""
    print("\n2. Testing Finding creation...")
    
    finding = Finding(
        vuln_type="XSS",
        url="http://example.com",
        parameter="search",
        payload="<script>alert(1)</script>",
        evidence="Found script tag in response",
        severity="HIGH",
        method="GET"
    )
    
    assert finding.vuln_type == "XSS"
    assert finding.severity == "HIGH"
    
    print("   ✓ Finding object creation works")
    return True


def test_logger():
    """Test logger setup"""
    print("\n3. Testing logger...")
    
    logger = setup_logger("test", verbose=False)
    logger.info("Test log message")
    
    print("   ✓ Logger initialization works")
    return True


def test_payload_loading():
    """Test payload file loading"""
    print("\n4. Testing payload files...")
    
    from config import PAYLOAD_DIR, XSS_PAYLOAD_FILE, SQLI_PAYLOAD_FILE
    
    xss_file = PAYLOAD_DIR / XSS_PAYLOAD_FILE
    sqli_file = PAYLOAD_DIR / SQLI_PAYLOAD_FILE
    
    assert xss_file.exists(), f"XSS payload file not found: {xss_file}"
    assert sqli_file.exists(), f"SQLi payload file not found: {sqli_file}"
    
    # Count payloads
    with open(xss_file, 'r') as f:
        xss_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    with open(sqli_file, 'r') as f:
        sqli_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"   ✓ Found {len(xss_payloads)} XSS payloads")
    print(f"   ✓ Found {len(sqli_payloads)} SQLi payloads")
    
    return True


def test_config_loading():
    """Test configuration loading"""
    print("\n5. Testing configuration...")
    
    import config
    
    assert hasattr(config, 'DEFAULT_THREADS')
    assert hasattr(config, 'DEFAULT_CRAWL_DEPTH')
    assert hasattr(config, 'PAYLOAD_DIR')
    
    print(f"   ✓ Default threads: {config.DEFAULT_THREADS}")
    print(f"   ✓ Default crawl depth: {config.DEFAULT_CRAWL_DEPTH}")
    print(f"   ✓ Payload directory: {config.PAYLOAD_DIR}")
    
    return True


def main():
    """Run all tests"""
    print("="*70)
    print("Web Application Vulnerability Scanner - Functional Tests")
    print("="*70)
    
    tests = [
        test_form_creation,
        test_finding_creation,
        test_logger,
        test_payload_loading,
        test_config_loading,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"   ❌ Test failed: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("✓ ALL TESTS PASSED!")
        print("\nThe scanner is ready to use. Try:")
        print("  cd scanner")
        print("  python main.py -u http://testphp.vulnweb.com --xss")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
