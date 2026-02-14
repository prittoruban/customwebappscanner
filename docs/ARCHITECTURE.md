# Architecture

> System design, data flow, and key design decisions for the Web Application Vulnerability Scanner v2.0.

---

## High-Level Pipeline

```
┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────┐
│  CLI      │────▶│  Crawler  │────▶│  Executor    │────▶│ Reporter │
│ (main.py) │     │ (BFS)     │     │ (ThreadPool) │     │ (HTML/   │
│           │     │           │     │              │     │  JSON/   │
│           │     │           │     │              │     │  Console)│
└──────────┘     └──────────┘     └──────────────┘     └──────────┘
                                         │
                                    ┌────┴────┐
                              ┌─────┤ Scanners├─────┐
                              │     └─────────┘     │
                              ▼                     ▼
                     ┌──────────────┐      ┌──────────────┐
                     │ Form-based   │      │ URL-based    │
                     │ (8 scanners) │      │ (headers)    │
                     └──────────────┘      └──────────────┘
                              │                     │
                              └─────────┬───────────┘
                                        ▼
                              ┌──────────────────┐
                              │ Post-Processing   │
                              │ • Chain Detector  │
                              │ • Remediation Gen │
                              └──────────────────┘
```

### Step-by-Step Flow

1. **CLI** (`main.py`) parses arguments, validates inputs, instantiates all components
2. **Crawler** (`crawler/crawler.py`) performs BFS crawl of the target, discovers pages and extracts HTML forms as `Form` objects
3. **Executor** (`engine/executor.py`) creates a `ThreadPoolExecutor`, distributes form × scanner and URL × scanner tasks in parallel
4. **Scanners** individually test each form/URL and return `Finding` objects
5. **Chain Detector** (`engine/chain_detector.py`) cross-references all findings to identify compound attack chains
6. **Remediation Generator** (`engine/remediation.py`) enriches each finding with framework-specific fix code
7. **Reporter** (`reporter/report.py`) renders findings to console, HTML, and/or JSON

---

## Core Data Model

### `Finding` (dataclass)

Central data structure used by every scanner, the executor, chain detector, remediation generator, and reporter.

```
Finding
├── vuln_type: str          # "XSS", "SQLi", "CSRF", etc.
├── url: str                # Target URL
├── parameter: str          # Affected parameter name
├── payload: str            # Payload that triggered the finding
├── evidence: str           # Response evidence
├── severity: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
├── method: str             # "GET" | "POST"
├── description: str        # Human-readable description
├── remediation: str        # Fix guidance + generated code
├── cwe_id: str             # e.g. "CWE-79"
├── owasp_category: str     # e.g. "A03:2021"
├── confidence: str         # "LOW" | "MEDIUM" | "HIGH"
├── scanner_module: str     # Which scanner found it
├── context: str            # Injection context (e.g. "html_attribute")
├── chain_id: Optional[str] # Links chained findings together
├── raw_request: str        # For reproduction
├── raw_response: str       # Response snippet
└── tags: List[str]         # Searchable tags
```

### `ScanResult` (dataclass)

Aggregate container for an entire scan session.

```
ScanResult
├── target_url: str
├── findings: List[Finding]
├── scan_duration: float
├── urls_crawled: int
├── forms_discovered: int
├── requests_made: int
├── errors: List[str]
├── scanner_version: str    # "2.0.0"
├── scan_config: Dict
├── total_findings (property)
├── critical_count (property)
├── high_count (property)
└── risk_score (property)   # Weighted: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
```

---

## Scanner Architecture

### BaseScanner (ABC)

All form-based scanners inherit from `scanner/base.py:BaseScanner`:

```python
class BaseScanner(ABC):
    @property
    @abstractmethod
    def scanner_name(self) -> str: ...

    @abstractmethod
    def scan_form(self, form: Form) -> List[Finding]: ...

    # Shared utilities:
    def scan(self, forms: List[Form]) -> List[Finding]
    def _load_payloads_from_file(self, filepath: str) -> List[str]
    def _get_testable_fields(self, form: Form) -> List[FormField]
    def _build_form_data(self, form, target_field, payload) -> Dict
    def _submit_form(self, form, form_data) -> Optional[Response]
```

**Exception:** `HeadersScanner` does not inherit `BaseScanner` because it scans URLs (not forms) via `scan_url(url)`.

### Scanner Detection Techniques

| Scanner | Key Technique | Implementation Detail |
|---|---|---|
| **XSS** | Canary probing → context detection → context-specific payloads → reflection verification | `_generate_canary()` → `_detect_context()` (6 contexts) → `CONTEXT_PAYLOADS` dict → `_verify_reflection()` (exact + decoded + partial) |
| **SQLi** | Three-phase: error → boolean-blind → time-based | `_check_error_based()` (regex + DB fingerprint) → `_check_boolean_blind()` (6 true/false pairs, SequenceMatcher) → `_check_time_based()` (baseline calibration) |
| **CSRF** | Token detection + entropy + active test | `CSRF_TOKEN_PATTERNS` matching → `_calculate_entropy()` Shannon → `_test_without_token()` replay |
| **SSRF** | Internal IP/cloud metadata injection | 30+ payloads covering localhost variants, AWS/Azure/GCP metadata, scheme tricks |
| **LFI** | Traversal + encoding bypass | 28+ payloads: `../`, null byte, double encoding, PHP wrappers; baseline comparison |
| **RCE** | Output + time-based blind | Command separators (`;`, `|`, `&&`, backtick, `$()`) + `sleep` timing |
| **Redirect** | Multi-vector redirect check | Location header, redirect chains, meta refresh, JavaScript `window.location` |
| **Headers** | Passive header/cookie check | 7 security headers, CSP directive analysis, CORS, cookie flags |

---

## Vulnerability Chain Detection

`engine/chain_detector.py` runs post-scan to identify compound attack paths.

### Chain Rules (7)

| Rule | Finding A | Finding B | Escalated Severity | Rationale |
|---|---|---|---|---|
| 1 | XSS | Missing CSP | CRITICAL | No CSP = unblocked script execution |
| 2 | CSRF | Missing SameSite cookie | HIGH | Token theft via cross-site form |
| 3 | Open Redirect | XSS | HIGH | Redirect used for phishing + XSS |
| 4 | SQLi | Missing HSTS | CRITICAL | Data exfil over downgraded connection |
| 5 | SSRF | LFI | CRITICAL | SSRF chains to local file read |
| 6 | Command Injection | Missing security headers | CRITICAL | RCE with no defense-in-depth |
| 7 | XSS | CSRF | CRITICAL | XSS steals CSRF token → account takeover |

Linked findings share a `chain_id` string.

---

## Auto-Remediation Engine

`engine/remediation.py` provides copy-paste-ready fix code for 8 vulnerability types across 4 frameworks:

| Vuln Type | Flask | Django | Express.js | PHP |
|---|:---:|:---:|:---:|:---:|
| XSS | ✓ | ✓ | ✓ | ✓ |
| SQLi | ✓ | ✓ | ✓ | ✓ |
| CSRF | ✓ | ✓ | ✓ | — |
| SSRF | ✓ | — | — | — |
| LFI | ✓ | — | — | — |
| RCE | ✓ | — | — | — |
| Open Redirect | ✓ | — | — | — |
| Security Headers | ✓ | — | ✓ | — |

The `enrich_findings()` method appends code to each `Finding.remediation` field based on the user's selected `--framework`.

---

## Threading Model

```
ScanExecutor
├── ThreadPoolExecutor(max_workers=N)
│   ├── Task: form₁ × XSSScanner
│   ├── Task: form₁ × SQLiScanner
│   ├── Task: form₁ × CSRFScanner
│   ├── Task: form₂ × XSSScanner
│   ├── ...
│   ├── Task: url₁ × HeadersScanner
│   └── Task: url₂ × HeadersScanner
│
├── results_lock (threading.Lock)
│   └── all_findings: List[Finding]
│
└── Post-scan (sequential):
    ├── VulnChainDetector.detect_chains()
    └── RemediationGenerator.enrich_findings()
```

- Form × scanner tasks run in parallel
- URL × scanner tasks (headers) run in parallel alongside form tasks
- Result collection is thread-safe via `threading.Lock`
- Post-scan enrichment (chain detection + remediation) runs sequentially after all scan tasks complete

---

## Configuration

All tunables are in `config.py`:

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_THREADS` | 5 | Worker threads |
| `MAX_THREADS` | 50 | Upper thread limit |
| `DEFAULT_CRAWL_DEPTH` | 2 | BFS crawl depth |
| `REQUEST_TIMEOUT` | 10s | HTTP timeout |
| `MAX_RETRIES` | 3 | Retry count |
| `REQUEST_DELAY` | 0.0s | Rate limiting delay |
| `VERIFY_SSL` | False | SSL certificate verification |
| `FOLLOW_REDIRECTS` | True | Follow HTTP redirects |
| `MAX_PAYLOADS_PER_INPUT` | 50 | Payload cap per field |
| `SQLI_BASELINE_SAMPLES` | 3 | Timing baseline samples |

---

## Report Pipeline

```
Findings
  │
  ├──▶ Console: severity-sorted table + chains + remediation sample
  │
  ├──▶ HTML: Jinja2 template (report.html)
  │         dark theme, stat cards, findings table,
  │         chain cards, remediation code blocks
  │
  └──▶ JSON: full schema with all 18 Finding fields,
             scan_info, statistics
```

The reporter uses `SEVERITY_LEVELS` from config for risk score calculation and `TEMPLATE_DIR` for Jinja2 template loading.
