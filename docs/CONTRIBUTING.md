# Contributing

> Development workflow, coding standards, and how to extend the scanner.

---

## Setup

```bash
git clone <repo-url> && cd customwebappscanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r scanner/requirements.txt
```

Verify everything works:

```bash
cd scanner
python3 tests/test_basic.py         # 34 tests, should all pass
python3 main.py --help               # CLI should display v2.0
```

---

## Project Layout

```
scanner/                ← All runtime code lives here
├── main.py             ← CLI entry point
├── config.py           ← Global constants
├── models/             ← Shared data models (Finding, ScanResult)
├── crawler/            ← BFS web crawler
├── scanner/            ← Vulnerability scanner modules (8)
├── engine/             ← Executor, chain detector, remediation
├── reporter/           ← Report generation (console/HTML/JSON)
├── payloads/           ← Payload text files
├── utils/              ← HTTP client, logging
└── tests/              ← Unit tests
```

---

## Adding a New Scanner

### 1. Create the Scanner Module

Create `scanner/scanner/yourscanner.py`:

```python
from typing import List
from scanner.base import BaseScanner
from models.finding import Finding
from crawler.crawler import Form
from config import CWE_MAPPINGS, OWASP_MAPPINGS

class YourScanner(BaseScanner):

    @property
    def scanner_name(self) -> str:
        return 'Your Vuln Type'

    def scan_form(self, form: Form) -> List[Finding]:
        findings = []
        testable = self._get_testable_fields(form)

        for field in testable:
            for payload in self.payloads:
                form_data = self._build_form_data(form, field, payload)
                response = self._submit_form(form, form_data)

                if response and self._is_vulnerable(response, payload):
                    findings.append(Finding(
                        vuln_type=self.scanner_name,
                        url=form.action,
                        parameter=field.name,
                        payload=payload,
                        evidence='your evidence here',
                        severity='HIGH',
                        method=form.method.upper(),
                        description='Description of what was found',
                        cwe_id=CWE_MAPPINGS.get(self.scanner_name, ''),
                        owasp_category=OWASP_MAPPINGS.get(self.scanner_name, ''),
                        scanner_module=self.scanner_name,
                    ))
        return findings

    def _is_vulnerable(self, response, payload) -> bool:
        # Your detection logic
        return False
```

### 2. Register in the Executor

In `engine/executor.py`, add:

```python
from scanner.yourscanner import YourScanner
```

Then in `execute_scan()`, add the enable flag and scanner initialization:

```python
if enable_yourscanner:
    form_scanners.append(("Your Type", YourScanner(self.http_client, p_dir)))
```

### 3. Add CLI Flag

In `main.py`, under the scan types group:

```python
scan_group.add_argument('--yourflag', action='store_true',
                        help='Your vulnerability description')
```

Wire it through `validate_arguments()` and the `execute_scan()` call.

### 4. Add Payloads (Optional)

Create `payloads/yourscanner.txt` with one payload per line. Comments start with `#`.

### 5. Add Config Entries

In `config.py`, add:
- `YOUR_PAYLOAD_FILE` path constant
- CWE mapping in `CWE_MAPPINGS`
- OWASP mapping in `OWASP_MAPPINGS`

### 6. Add Remediation Templates (Optional)

In `engine/remediation.py`, add an entry in `REMEDIATION_TEMPLATES`:

```python
'Your Vuln Type': {
    'python_flask': {
        'title': 'Flask Fix for Your Vuln',
        'code': '''# Your fix code here...'''
    },
},
```

### 7. Add Tests

Add a test class in `tests/test_basic.py`:

```python
def test_your_scanner(self):
    from scanner.yourscanner import YourScanner
    c = self._client()
    s = YourScanner(c)
    self.assertEqual(s.scanner_name, 'Your Vuln Type')
    c.close()
```

---

## Coding Standards

### Python

- Python 3.10+ — use modern type hints (`list[str]` or `List[str]` from typing)
- All modules must have a module-level docstring
- All public classes and methods must have docstrings
- Use absolute imports from the `scanner/` package root:
  ```python
  from models.finding import Finding     # correct
  from config import MAX_THREADS         # correct
  from ..models.finding import Finding   # WRONG — relative imports break script execution
  ```
- Dataclasses for data models, `ABC` for interfaces
- No circular imports — the dependency graph is:
  ```
  config ← utils ← models ← scanner ← engine ← reporter ← main
  ```

### Naming

- Modules: `lowercase.py`
- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

### Files

- Scanner modules → `scanner/scanner/`
- Engine components → `scanner/engine/`
- One class per file (exceptions: small dataclasses can share a file)
- Payload files → `scanner/payloads/`, one payload per line, `#` comments

---

## Testing

### Running Tests

```bash
cd scanner
python3 tests/test_basic.py     # verbose output + 34 tests
```

### Test Coverage

| Area | Tests |
|---|---|
| Module imports | 7 tests — all 18 modules |
| Finding model | 3 tests — creation, defaults, field completeness |
| ScanResult | 2 tests — empty + populated |
| Chain detector | 2 tests — chain found + no chain |
| Remediation | 3 tests — Flask, Django, unknown type |
| Scanner instantiation | 8 tests — all scanners |
| Executor | 2 tests — init + empty scan |
| Reporter | 2 tests — console + JSON |
| Config | 4 tests — paths, headers, CWE, threads |
| Payload files | 1 test — existence + non-empty |

### Writing Tests

- Use `unittest.TestCase`
- Always `sys.path.insert(0, ...)` for proper imports
- Test scanners via instantiation (no network calls in unit tests)
- Test chain detection and remediation with in-memory `Finding` objects

---

## Payload Files

Located in `scanner/payloads/`. One payload per line. Lines starting with `#` are comments.

| File | Content |
|---|---|
| `xss.txt` | XSS vectors (script tags, event handlers, encoding bypasses) |
| `sqli.txt` | SQL injection payloads (error-based, boolean, time-based) |
| `ssrf.txt` | SSRF payloads (localhost, cloud metadata, scheme tricks) |
| `lfi.txt` | Path traversal (traversal sequences, null bytes, PHP wrappers) |
| `cmdi.txt` | Command injection (separators, subshells, encoding) |
| `redirect.txt` | Open redirect (protocol-relative, domain confusion, schemes) |

Scanners use `BaseScanner._load_payloads_from_file()` to load these, with built-in fallback payloads if the file is missing.

---

## Commit Guidelines

- Prefix: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- One logical change per commit
- Run tests before committing:
  ```bash
  cd scanner && python3 tests/test_basic.py
  ```

---

## Architecture Docs

For system design details, data flow diagrams, and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

For complete API reference with all method signatures, see [API.md](API.md).
