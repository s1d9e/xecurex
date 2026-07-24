<p align="center">
  <img src="https://img.shields.io/badge/XecureX-2.0.0-ff4444?style=for-the-badge&logo=shield&logoColor=white" alt="XecureX">
</p>

<h1 align="center">⚡ XecureX</h1>

<p align="center">
  <strong>Open-source security audit tool for source code</strong><br>
  Detects hardcoded secrets, SQL injection, XSS, command injection, weak crypto, and more.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-00FF00?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0.0-ff4444?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Tests-68%20passed-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square" alt="CI">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#cli">CLI</a> •
  <a href="#output">Output</a> •
  <a href="#development">Dev</a> •
  <a href="docs/RULES.md">All Rules</a>
</p>

---

## Features

| Capability | Details |
|------------|---------|
| **AST-based analysis** | Python `ast` module — precise, context-aware |
| **66+ detection patterns** | 9 categories: CRED, INJECT, XSS, CRYPTO, DESERN, PATH, EXPOSE, HARDCODE, DEP |
| **Comment-aware** | Ignores code inside comments and docstrings |
| **Confidence scoring** | Each finding rated 0.0–1.0 |
| **Multi-language** | Python, JS, TS, Java, Go, PHP, Ruby, C#, Shell, SQL |
| **CI/CD ready** | JSON output, exit codes, Docker, GitHub Actions |
| **Configurable** | Severity filter, confidence threshold, custom excludes |

---

## Quick Start

```bash
# Install
git clone https://github.com/s1d9e/xecurex.git && cd xecurex
pip install -e .

# Scan
xecurex /path/to/repo

# JSON report
xecurex /path/to/repo --format json -o report.json

# Only HIGH severity
xecurex /path/to/repo --min-severity high
```

---

## CLI

```
xecurex [OPTIONS] PATH
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format {text,json}` | Output format | `text` |
| `-o, --output FILE` | Save to file | stdout |
| `--min-severity {low,medium,high}` | Filter by severity | `low` |
| `--exclude DIR ...` | Exclude directories | — |
| `--no-ast` | Disable Python AST (regex only) | off |
| `--min-confidence FLOAT` | Min confidence 0.0–1.0 | `0.3` |
| `-v, --verbose` | Show scan progress | off |
| `--version` | Show version | — |

| Exit Code | Meaning |
|-----------|---------|
| `0` | No issues found |
| `1` | Issues detected |
| `2` | Error |

---

## Output

```
======================================================================
                    SECURITY AUDIT REPORT
======================================================================

  Files scanned:  42
  Lines scanned:  1583
  Scan duration:  0.12s

  Found 5 potential security issues:
    HIGH: 2  MEDIUM: 2  LOW: 1

  !!! HIGH Severity (2)
  --------------------------------------------------
    src/auth.py:15
      [CRED-001] Hardcoded password detected
      Confidence: [#########.]. (90%)
      Code: password = "supersecret123"

  !  MEDIUM Severity (2)
  --------------------------------------------------
    frontend/app.js:23
      [XSS-001] Dangerous innerHTML assignment
      Confidence: [########..]. (80%)
      Code: .innerHTML = userInput

  i  LOW Severity (1)
  --------------------------------------------------
    src/config.py:5
      [HARDCODE-002] Insecure HTTP URL
      Confidence: [######....]. (60%)
      Code: http://api.example.com/v1/users
```

### JSON

```json
{
  "stats": { "files_scanned": 42, "lines_scanned": 1583 },
  "findings": [
    {
      "file": "src/auth.py",
      "line": 15,
      "category": "Hardcoded Credentials",
      "severity": "HIGH",
      "rule_id": "CRED-001",
      "confidence": 0.9,
      "match": "password = \"supersecret123\""
    }
  ],
  "summary": { "total": 5, "high": 2, "medium": 2, "low": 1 }
}
```

---

## Configuration

Create `xecurex.toml` or add to `pyproject.toml`:

```toml
[xecurex]
exclude_dirs = ["test_data", "fixtures"]
min_severity = "medium"
use_ast = true
confidence_threshold = 0.5
```

CLI flags override file configuration.

---

## Docker

```bash
docker build -t xecurex .
docker run --rm -v /path/to/repo:/repo xecurex /repo
```

---

## Development

```bash
make install    # Install dev dependencies
make test       # Run tests with coverage
make lint       # Lint (ruff)
make format     # Format (ruff)
make scan       # Scan self
```

---

## Project Structure

```
src/xecurex/
├── cli.py                  # CLI entry point
├── scanner.py              # Scan orchestration
├── reporter.py             # Text + JSON reports
├── models.py               # Finding, ScanResult dataclasses
├── config.py               # Configuration
├── rules/                  # 9 rule categories (66+ patterns)
│   ├── base.py             # Abstract Rule class
│   ├── credentials.py      # CRED
│   ├── injection.py        # INJECT
│   ├── xss.py              # XSS
│   ├── crypto.py           # CRYPTO
│   ├── deserialization.py  # DESERN
│   ├── path_traversal.py   # PATH
│   ├── data_exposure.py    # EXPOSE
│   ├── hardcoded.py        # HARDCODE
│   └── dependencies.py     # DEP
└── analyzers/
    ├── generic_analyzer.py  # Regex (all languages)
    └── python_analyzer.py   # AST (Python)
```

---

## Contributing

1. Fork → Branch → Commit → Push → PR
2. Add tests for new rules/features
3. Run `make lint && make test` before submitting

---

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

> This tool is for authorized security testing only. Always ensure you have permission before scanning code you do not own.

---

<p align="center">
  Built by <a href="https://github.com/s1d9e">s1d9e</a>
</p>
