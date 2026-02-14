# API Reference

> Module-level API documentation for every public class and method in the scanner.

---

## Table of Contents

- [models.finding](#modelsfinding)
- [scanner.base](#scannerbase)
- [scanner.xss](#scannerxss)
- [scanner.sqli](#scannersqli)
- [scanner.csrf](#scannercsrf)
- [scanner.ssrf](#scannerssrf)
- [scanner.lfi](#scannerlfi)
- [scanner.cmdi](#scannercmdi)
- [scanner.redirect](#scannerredirect)
- [scanner.headers](#scannerheaders)
- [engine.executor](#engineexecutor)
- [engine.chain_detector](#enginechain_detector)
- [engine.remediation](#engineremediation)
- [crawler.crawler](#crawlercrawler)
- [reporter.report](#reporterreport)
- [utils.http](#utilshttp)
- [utils.logger](#utilslogger)
- [config](#config)

---

## models.finding

**Module:** `scanner/models/finding.py`

### `SeverityLevel(Enum)`

Enumeration for vulnerability severity with integer ordering.

| Value | Weight |
|---|---|
| `CRITICAL` | 4 |
| `HIGH` | 3 |
| `MEDIUM` | 2 |
| `LOW` | 1 |
| `INFO` | 0 |

Supports comparison operators (`<`, `<=`, `>`, `>=`).

---

### `Finding` (dataclass)

Represents a single vulnerability finding. Used by every scanner, the executor, chain detector, remediation engine, and reporter.

**Required fields:**

| Field | Type | Description |
|---|---|---|
| `vuln_type` | `str` | Vulnerability class: `"XSS"`, `"SQLi"`, `"CSRF"`, `"SSRF"`, `"LFI"`, `"Command Injection"`, `"Open Redirect"`, `"Security Headers"` |
| `url` | `str` | Target URL where vulnerability was found |
| `parameter` | `str` | Affected input parameter |
| `payload` | `str` | Payload that triggered the finding |
| `evidence` | `str` | Response evidence confirming the vulnerability |
| `severity` | `str` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"INFO"` |
| `method` | `str` | HTTP method (`"GET"` or `"POST"`) — default: `"GET"` |
| `description` | `str` | Human-readable description |

**Optional fields (defaults provided):**

| Field | Type | Default | Description |
|---|---|---|---|
| `remediation` | `str` | `""` | Fix guidance + generated code |
| `cwe_id` | `str` | `""` | CWE identifier (e.g. `"CWE-79"`) |
| `owasp_category` | `str` | `""` | OWASP Top 10 ref (e.g. `"A03:2021"`) |
| `confidence` | `str` | `"MEDIUM"` | Detection confidence |
| `scanner_module` | `str` | `""` | Scanner that found it |
| `context` | `str` | `""` | Injection context |
| `chain_id` | `Optional[str]` | `None` | Links chained findings |
| `raw_request` | `str` | `""` | Raw HTTP request |
| `raw_response` | `str` | `""` | Response snippet |
| `tags` | `List[str]` | `[]` | Searchable tags |

---

### `ScanResult` (dataclass)

Aggregate container for a full scan session.

**Fields:**

| Field | Type | Default |
|---|---|---|
| `target_url` | `str` | — |
| `findings` | `List[Finding]` | `[]` |
| `scan_duration` | `float` | `0.0` |
| `urls_crawled` | `int` | `0` |
| `forms_discovered` | `int` | `0` |
| `requests_made` | `int` | `0` |
| `errors` | `List[str]` | `[]` |
| `scanner_version` | `str` | `"2.0.0"` |
| `scan_config` | `Dict[str, Any]` | `{}` |

**Properties:**

| Property | Returns | Description |
|---|---|---|
| `total_findings` | `int` | `len(findings)` |
| `critical_count` | `int` | Count of CRITICAL findings |
| `high_count` | `int` | Count of HIGH findings |
| `risk_score` | `int` | Weighted sum: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1 |

---

## scanner.base

**Module:** `scanner/scanner/base.py`

### `BaseScanner(ABC)`

Abstract base class for all form-based scanners.

**Constructor:**

```python
BaseScanner(http_client: HTTPClient, payload_file: str = None)
```

| Param | Type | Description |
|---|---|---|
| `http_client` | `HTTPClient` | Shared HTTP client instance |
| `payload_file` | `str \| None` | Path to payload file; falls back to built-in payloads |

**Abstract members:**

| Member | Type | Description |
|---|---|---|
| `scanner_name` | `property → str` | Human-readable name (e.g. `"XSS"`) |
| `scan_form(form)` | `method → List[Finding]` | Scan a single form |

**Concrete methods:**

| Method | Signature | Description |
|---|---|---|
| `scan` | `(forms: List[Form]) → List[Finding]` | Iterate over all forms, call `scan_form()` on each |
| `_load_payloads_from_file` | `(filepath: str) → List[str]` | Load payloads from file; strips comments/blanks |
| `_get_testable_fields` | `(form: Form) → List[FormField]` | Filter form fields to testable inputs |
| `_build_form_data` | `(form, target_field, payload) → Dict` | Build form data dict with payload injected into target field |
| `_submit_form` | `(form, form_data) → Optional[Response]` | Submit form via HTTP (GET or POST based on form.method) |

---

## scanner.xss

**Module:** `scanner/scanner/xss.py`

### `XSSScanner(BaseScanner)`

Context-aware Cross-Site Scripting scanner.

**`scanner_name`** → `"XSS"`

**Detection flow:**
1. Inject canary string → detect reflection context
2. Select context-specific payloads from `CONTEXT_PAYLOADS`
3. Verify reflection (exact match → HTML-decoded → partial critical fragment)
4. Calculate severity based on context

**Key internal methods:**

| Method | Description |
|---|---|
| `_generate_canary()` | Random alphanumeric canary string |
| `_detect_context(response, canary)` | Returns context: `html_body`, `html_attribute`, `javascript`, `url`, `css`, `unknown` |
| `_get_payloads_for_context(context)` | Context-specific payloads from `CONTEXT_PAYLOADS` |
| `_verify_reflection(response, payload)` | Three-tier verification |
| `_calculate_severity(context)` | CRITICAL for script/JS, HIGH for attribute/URL, MEDIUM otherwise |

---

## scanner.sqli

**Module:** `scanner/scanner/sqli.py`

### `SQLiScanner(BaseScanner)`

Differential response SQL Injection scanner.

**`scanner_name`** → `"SQLi"`

**Detection phases:**
1. **Error-based:** Regex pattern matching + DB fingerprinting
2. **Boolean-blind:** 6 true/false payload pairs + `SequenceMatcher` response similarity
3. **Time-based:** `sleep`/`waitfor` payloads with baseline calibration

**Key internal methods:**

| Method | Description |
|---|---|
| `_measure_baseline(form, field)` | Average response time over `SQLI_BASELINE_SAMPLES` clean requests |
| `_check_error_based(form, field)` | Regex match against `SQLI_ERROR_PATTERNS` |
| `_check_boolean_blind(form, field)` | Compare true/false response similarity (threshold: < 0.85) |
| `_check_time_based(form, field)` | Timing delta against calibrated baseline |
| `_fingerprint_db(response_text)` | Identify DB engine from `DB_FINGERPRINTS` |

---

## scanner.csrf

**Module:** `scanner/scanner/csrf.py`

### `CSRFScanner(BaseScanner)`

CSRF scanner with token entropy analysis.

**`scanner_name`** → `"CSRF"`

**Key internal methods:**

| Method | Description |
|---|---|
| `_calculate_entropy(token)` | Shannon entropy (bits/char) |
| `_test_without_token(form)` | Active test: submit form without CSRF token |

Checks: token presence → pattern matching → entropy (threshold: ≥ 3.0 bits/char, ≥ 16 chars) → active testing.

---

## scanner.ssrf

**Module:** `scanner/scanner/ssrf.py`

### `SSRFScanner(BaseScanner)`

**`scanner_name`** → `"SSRF"`

30+ built-in payloads covering: localhost variants, internal networks, AWS/Azure/GCP metadata endpoints, `file://`/`gopher://`/`dict://` schemes.

Prioritizes URL-like parameter names (`url`, `link`, `redirect`, `src`, `href`, etc.).

---

## scanner.lfi

**Module:** `scanner/scanner/lfi.py`

### `LFIScanner(BaseScanner)`

**`scanner_name`** → `"LFI"`

28+ payloads: directory traversal, null byte bypass, double encoding, PHP wrappers. Baseline response comparison to reduce false positives.

---

## scanner.cmdi

**Module:** `scanner/scanner/cmdi.py`

### `CommandInjectionScanner(BaseScanner)`

**`scanner_name`** → `"Command Injection"`

Output-based detection (command separators + response indicators) and time-based blind detection (baseline-calibrated `sleep` timing).

---

## scanner.redirect

**Module:** `scanner/scanner/redirect.py`

### `RedirectScanner(BaseScanner)`

**`scanner_name`** → `"Open Redirect"`

Checks: `Location` header, redirect chain following, `<meta http-equiv="refresh">`, JavaScript `window.location` patterns.

Targets redirect-like parameters: `url`, `next`, `return`, `redirect`, `goto`, etc.

---

## scanner.headers

**Module:** `scanner/scanner/headers.py`

### `HeadersScanner`

> **Note:** Does NOT inherit `BaseScanner`. Scans URLs, not forms.

**Constructor:**

```python
HeadersScanner(http_client: HTTPClient)
```

**Public method:**

```python
scan_url(url: str) -> List[Finding]
```

**Checks performed:**
- Missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection)
- CSP directive analysis (unsafe-inline, unsafe-eval, data:, wildcard *)
- CORS misconfiguration (wildcard `Access-Control-Allow-Origin`)
- Information disclosure (Server, X-Powered-By, ASP.NET version)
- Cookie security flags (Secure, HttpOnly, SameSite)

---

## engine.executor

**Module:** `scanner/engine/executor.py`

### `ScanExecutor`

Multi-threaded scan orchestrator.

**Constructor:**

```python
ScanExecutor(http_client: HTTPClient, max_workers: int = DEFAULT_THREADS)
```

**Main method:**

```python
execute_scan(
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
) -> List[Finding]
```

Returns enriched findings (with chain IDs and remediation code).

**Also provides:**

```python
execute_scan_sequential(...)  # Same signature, single-threaded for debugging
```

---

## engine.chain_detector

**Module:** `scanner/engine/chain_detector.py`

### `VulnChainDetector`

**Method:**

```python
detect_chains(findings: List[Finding]) -> List[Dict]
```

Returns list of detected chains. Each chain is a dict with `rule`, `findings`, and `chain_id`. Modifies findings in-place by setting `chain_id` and escalating `severity`.

7 built-in rules — see [ARCHITECTURE.md](ARCHITECTURE.md#vulnerability-chain-detection).

---

## engine.remediation

**Module:** `scanner/engine/remediation.py`

### `RemediationGenerator`

**Methods:**

```python
get_remediation(finding: Finding, framework: str = "python_flask") -> Dict
# Returns: {'title': str, 'code': str, 'available_frameworks': List[str]}

enrich_findings(findings: List[Finding], framework: str = "python_flask") -> List[Finding]
# Modifies findings in-place, appending code to finding.remediation
```

Covers 8 vuln types × up to 4 frameworks. Falls back to first available framework if requested one has no template.

---

## crawler.crawler

**Module:** `scanner/crawler/crawler.py`

### `FormField` (dataclass)

| Field | Type |
|---|---|
| `name` | `str` |
| `field_type` | `str` |
| `value` | `str` |

### `Form` (dataclass)

| Field | Type |
|---|---|
| `action` | `str` |
| `method` | `str` |
| `fields` | `List[FormField]` |

### `WebCrawler`

```python
WebCrawler(start_url: str, max_depth: int, http_client: HTTPClient)
```

| Method | Returns | Description |
|---|---|---|
| `crawl()` | `List[Form]` | BFS crawl; returns all discovered forms |

| Attribute | Type | Description |
|---|---|---|
| `visited_urls` | `Set[str]` | All URLs visited during crawl |

---

## reporter.report

**Module:** `scanner/reporter/report.py`

### `ReportGenerator`

```python
generate_console_report(findings: List[Finding], target_url: str)
generate_html_report(findings, target_url, output_file=None) -> Path
generate_json_report(findings, target_url, output_file=None) -> Path
generate_reports(findings, target_url, formats=None) -> Dict[str, Path]
```

- Console: prints severity table, chains summary, remediation sample
- HTML: Jinja2 dark-themed template with stat cards, chains, remediation code blocks
- JSON: full 18-field Finding schema, scan_info metadata, statistics

---

## utils.http

**Module:** `scanner/utils/http.py`

### `HTTPClient`

Wrapper around `requests.Session` with retry, rate limiting, and config integration.

```python
HTTPClient()
```

| Method | Signature | Description |
|---|---|---|
| `get` | `(url, params=None, **kwargs) → Response` | GET request with retries |
| `post` | `(url, data=None, json=None, **kwargs) → Response` | POST request |
| `head` | `(url, **kwargs) → Response` | HEAD request |
| `close` | `()` | Close underlying session |

| Attribute | Type | Description |
|---|---|---|
| `request_count` | `int` | Total requests made |

Reads `REQUEST_TIMEOUT`, `MAX_RETRIES`, `USER_AGENT`, `REQUEST_DELAY`, `VERIFY_SSL`, `FOLLOW_REDIRECTS` from `config.py`.

---

## utils.logger

**Module:** `scanner/utils/logger.py`

```python
setup_logger(name: str, verbose: bool = False) -> Logger
get_logger(name: str) -> Logger
```

- `verbose=True` → DEBUG level
- `verbose=False` → INFO level
- Format: `[LEVEL] name: message`

---

## config

**Module:** `scanner/config.py`

All global configuration constants. Key exports:

| Constant | Value | Purpose |
|---|---|---|
| `PROJECT_ROOT` | `Path` | Root of scanner package |
| `PAYLOAD_DIR` | `Path` | Payload files directory |
| `REPORT_DIR` | `Path` | Generated reports directory |
| `TEMPLATE_DIR` | `Path` | Jinja2 templates directory |
| `DEFAULT_THREADS` | `5` | Default worker count |
| `MAX_THREADS` | `50` | Maximum workers |
| `DEFAULT_CRAWL_DEPTH` | `2` | Default BFS depth |
| `REQUEST_TIMEOUT` | `10` | HTTP timeout (seconds) |
| `MAX_RETRIES` | `3` | Retry count |
| `VERIFY_SSL` | `False` | SSL verification |
| `MAX_PAYLOADS_PER_INPUT` | `50` | Payload cap per field |
| `SEVERITY_LEVELS` | `Dict` | Severity → weight mapping |
| `REPORT_FORMATS` | `List` | Available report formats |
| `CWE_MAPPINGS` | `Dict` | Vuln type → CWE ID |
| `OWASP_MAPPINGS` | `Dict` | Vuln type → OWASP category |
| `SECURITY_HEADERS` | `Dict` | Expected security headers + metadata |
| `SQLI_ERROR_PATTERNS` | `List` | Compiled regex patterns for SQLi errors |
| `XSS_CONTEXTS` | `Dict` | Context detection regex patterns |
| `CSRF_TOKEN_PATTERNS` | `List` | CSRF token name patterns |
