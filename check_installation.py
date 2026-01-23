#!/usr/bin/env python3
"""
Installation verification script.

Run this to verify that all dependencies are installed correctly.
"""

import sys
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.10+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print("❌ Python 3.10+ required. Current version: {}.{}.{}".format(
            version.major, version.minor, version.micro
        ))
        return False
    print(f"✓ Python version: {version.major}.{version.minor}.{version.micro}")
    return True

def check_dependencies():
    """Check if all required packages are installed"""
    required_packages = [
        'requests',
        'bs4',  # beautifulsoup4
        'jinja2',
        'urllib3'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} installed")
        except ImportError:
            print(f"❌ {package} NOT installed")
            missing.append(package)
    
    return len(missing) == 0

def check_project_structure():
    """Check if all required files exist"""
    base_path = Path(__file__).parent / 'scanner'
    
    required_files = [
        'main.py',
        'config.py',
        'requirements.txt',
        'crawler/crawler.py',
        'scanner/xss.py',
        'scanner/sqli.py',
        'scanner/csrf.py',
        'engine/executor.py',
        'reporter/report.py',
        'reporter/templates/report.html',
        'payloads/xss.txt',
        'payloads/sqli.txt',
        'utils/http.py',
        'utils/logger.py',
    ]
    
    missing = []
    for file_path in required_files:
        full_path = base_path / file_path
        if not full_path.exists():
            print(f"❌ Missing: {file_path}")
            missing.append(file_path)
        else:
            print(f"✓ {file_path}")
    
    return len(missing) == 0

def main():
    """Run all checks"""
    print("="*70)
    print("Web Application Vulnerability Scanner - Installation Check")
    print("="*70)
    
    print("\n1. Checking Python version...")
    python_ok = check_python_version()
    
    print("\n2. Checking dependencies...")
    deps_ok = check_dependencies()
    
    print("\n3. Checking project structure...")
    structure_ok = check_project_structure()
    
    print("\n" + "="*70)
    
    if python_ok and deps_ok and structure_ok:
        print("✓ ALL CHECKS PASSED!")
        print("\nYou're ready to use the scanner. Try:")
        print("  cd scanner")
        print("  python main.py --help")
        return 0
    else:
        print("❌ SOME CHECKS FAILED")
        if not python_ok:
            print("\n→ Upgrade Python to 3.10 or higher")
        if not deps_ok:
            print("\n→ Install dependencies:")
            print("    cd scanner")
            print("    pip install -r requirements.txt")
        if not structure_ok:
            print("\n→ Some files are missing. Re-download the project.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
