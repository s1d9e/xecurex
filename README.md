<p align="center">
  <br>
  <img src="https://img.shields.io/badge/XecureX-2.0.0-ff4444?style=for-the-badge&logo=shield&logoColor=white" alt="XecureX">
  <br><br>
</p>

<h1 align="center">
  <br>
  ⚡ XecureX
  <br>
</h1>

<h4 align="center">Open-source security audit tool for source code</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-00FF00?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0.0-ff4444?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Tests-68%20passed-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Rules-66+-ff6600?style=flat-square" alt="Rules">
  <img src="https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square" alt="CI">
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-detection-engine">Detection</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-cli-reference">CLI</a> •
  <a href="#-configuration">Config</a> •
  <a href="#-output">Output</a> •
  <a href="#-development">Dev</a> •
  <a href="#-license">License</a>
</p>

<p align="center">
  Detects hardcoded secrets, SQL injection, XSS, command injection, weak crypto,<br>
  insecure deserialization, path traversal, and more — across Python, JavaScript,<br>
  TypeScript, Java, Go, PHP, Ruby, C#, Shell, and SQL.
</p>

---

## Table of Contents

- [Features](#-features)
- [Detection Engine](#-detection-engine)
- [Rules Reference](#-rules-reference)
- [Quick Start](#-quick-start)
- [CLI Reference](#-cli-reference)
- [Configuration](#-configuration)
- [Output](#-output)
- [JSON Schema](#-json-schema)
- [Docker](#-docker)
- [Development](#-development)
- [Project Structure](#-project-structure)
- [Exit Codes](#-exit-codes)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

---

## Features

<table>
<tr>
<td width="50%" valign="top">

### Core Capabilities

- **AST-based analysis** for Python (native `ast` module)
- **66+ detection patterns** across 9 vulnerability categories
- **Comment-aware scanning** — ignores code in comments
- **Confidence scoring** — every finding has a confidence level
- **Deduplication** — no duplicate findings on same line
- **Configurable severity** — filter by HIGH, MEDIUM, LOW

</td>
<td width="50%" valign="top">

### Developer Experience

- **CLI** with colored output and progress bar
- **JSON output** for CI/CD integration
- **Config files** (`xecurex.toml` / `pyproject.toml`)
- **Exit codes** for pipeline automation
- **Docker** support out of the box
- **68 tests** ensuring reliability

</td>
</tr>
</table>

---

## Detection Engine

XecureX uses a **dual-engine approach** for maximum coverage:

| Language | Engine | Precision | Speed |
|----------|--------|-----------|-------|
| Python | **AST Parsing** + Regex | ★★★★★ | Fast |
| JavaScript / TypeScript | Regex (improved) | ★★★★☆ | Fast |
| Java | Regex (improved) | ★★★★☆ | Fast |
| Go | Regex (improved) | ★★★★☆ | Fast |
| PHP | Regex (improved) | ★★★★☆ | Fast |
| Ruby | Regex (improved) | ★★★★☆ | Fast |
| C# | Regex (improved) | ★★★★☆ | Fast |
| Shell | Regex (improved) | ★★★☆☆ | Fast |
| SQL | Regex (improved) | ★★★☆☆ | Fast |

### How It Works

```
Source Code
    │
    ▼
┌─────────────────┐
│  File Discovery  │  ── Excludes: node_modules, .git, venv, build...
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Language Detect │  ── Selects appropriate analyzer
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│  AST   │ │ Regex  │
│Analyzer│ │Analyzer│
└────┬───┘ └────┬───┘
     │          │
     └────┬─────┘
          ▼
┌─────────────────┐
│  Rule Matching   │  ── 66+ patterns across 9 categories
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Deduplication   │  ── Removes overlapping findings
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Confidence      │  ── Scores each finding 0.0–1.0
│  Scoring         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Report          │  ── Text (colored) or JSON
└─────────────────┘
```

---

## Rules Reference

### CRED — Hardcoded Credentials

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `CRED-001` | Hardcoded password detected | HIGH | 90% |
| `CRED-002` | Hardcoded API key detected | HIGH | 85% |
| `CRED-003` | Hardcoded secret detected | HIGH | 80% |
| `CRED-004` | Hardcoded auth/access token | HIGH | 85% |
| `CRED-005` | AWS credentials in code | HIGH | 90% |
| `CRED-006` | Hardcoded private key | HIGH | 95% |
| `CRED-007` | Hardcoded password/credential | HIGH | 75% |
| `CRED-008` | Hardcoded token | HIGH | 70% |

### INJECT — Injection Vulnerabilities

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `INJECT-001` | SQL query with string concatenation | HIGH | 85% |
| `INJECT-002` | SQL query with %-formatting | HIGH | 85% |
| `INJECT-003` | f-string SQL query | HIGH | 80% |
| `INJECT-004` | SQL query concatenating variable | HIGH | 80% |
| `INJECT-005` | `os.system()` call | HIGH | 90% |
| `INJECT-006` | `subprocess` with `shell=True` | HIGH | 90% |
| `INJECT-007` | `eval()` usage | HIGH | 85% |
| `INJECT-008` | `exec()` usage | HIGH | 80% |
| `INJECT-009` | `os.popen()` call | HIGH | 85% |
| `INJECT-010` | `new Function()` (JS) | HIGH | 85% |

### XSS — Cross-Site Scripting

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `XSS-001` | Dangerous `innerHTML` assignment | MEDIUM | 80% |
| `XSS-002` | `document.write()` usage | MEDIUM | 75% |
| `XSS-003` | React `dangerouslySetInnerHTML` | MEDIUM | 80% |
| `XSS-004` | Dangerous `outerHTML` assignment | MEDIUM | 80% |
| `XSS-005` | `insertAdjacentHTML` | MEDIUM | 80% |

### CRYPTO — Weak Cryptography

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `CRYPTO-001` | MD5 hash usage | MEDIUM | 90% |
| `CRYPTO-002` | SHA-1 hash usage | MEDIUM | 90% |
| `CRYPTO-003` | Weak hash via `hashlib.new()` | MEDIUM | 90% |
| `CRYPTO-004` | Weak symmetric cipher | MEDIUM | 85% |
| `CRYPTO-005` | `Math.random()` (not crypto-safe) | LOW | 60% |

### DESERN — Insecure Deserialization

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `DESERN-001` | `pickle.load()` / `pickle.loads()` | HIGH | 95% |
| `DESERN-002` | `yaml.load()` without Loader | HIGH | 90% |
| `DESERN-003` | `yaml.unsafe_load()` | HIGH | 95% |
| `DESERN-004` | `marshal.loads()` | HIGH | 90% |
| `DESERN-005` | `shelve.open()` (uses pickle) | MEDIUM | 80% |
| `DESERN-006` | PHP `unserialize()` | HIGH | 90% |

### PATH — Path Traversal

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `PATH-001` | Dynamic file path in `open()` | MEDIUM | 70% |
| `PATH-002` | `../` pattern detected | MEDIUM | 50% |
| `PATH-003` | Node.js `readFileSync` + dynamic | MEDIUM | 70% |

### EXPOSE — Sensitive Data Exposure

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `EXPOSE-001` | Sensitive data in `console.log()` | LOW | 70% |
| `EXPOSE-002` | Sensitive data in `print()` | LOW | 65% |
| `EXPOSE-003` | Sensitive data in logging call | LOW | 60% |

### HARDCODE — Hardcoded IP/URL

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `HARDCODE-001` | Hardcoded IP address | LOW | 50% |
| `HARDCODE-002` | Insecure HTTP URL | LOW | 60% |

### DEP — Insecure Dependencies

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `DEP-001` | Node.js `crypto` module | LOW | 40% |
| `DEP-002` | JWT library usage | LOW | 50% |
| `DEP-003` | `eval` npm package | MEDIUM | 80% |
| `DEP-004` | `telnetlib` (unencrypted) | MEDIUM | 80% |

---

## Quick Start

### Install

```bash
git clone https://github.com/s1d9e/xecurex.git
cd xecurex
pip install -e ".[dev]"
```

### Scan a Repository

```bash
# Basic scan
xecurex /path/to/your/repo

# Scan with colored output
xecurex ~/my-project

# Scan current directory
xecurex .
```

### Common Workflows

```bash
# Security audit before deployment
xecurex /path/to/repo --min-severity high

# Generate report for CI/CD
xecurex /path/to/repo --format json --output report.json

# Scan only Python files with AST
xecurex /path/to/repo --exclude frontend/ docs/

# Quick scan (regex only, no AST)
xecurex /path/to/repo --no-ast --verbose
```

---

## CLI Reference

```
usage: xecurex [-h] [--format {text,json}] [-o OUTPUT]
               [--min-severity {low,medium,high}] [--exclude [EXCLUDE ...]]
               [--no-ast] [--no-config] [--min-confidence MIN_CONFIDENCE]
               [-v] [--version]
               path
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `path` | Path to directory or repository to scan | *(required)* |
| `--format {text,json}` | Output format | `text` |
| `-o, --output OUTPUT` | Write results to file instead of stdout | stdout |
| `--min-severity {low,medium,high}` | Minimum severity to report | `low` |
| `--exclude [DIR ...]` | Additional directories to exclude | — |
| `--no-ast` | Disable Python AST analysis (regex only) | AST enabled |
| `--no-config` | Ignore `xecurex.toml` / `pyproject.toml` config | Config enabled |
| `--min-confidence FLOAT` | Minimum confidence threshold (0.0–1.0) | `0.3` |
| `-v, --verbose` | Show scan progress | off |
| `--version` | Show version and exit | — |
| `-h, --help` | Show help message and exit | — |

### Exit Codes

| Code | Meaning | Use Case |
|------|---------|----------|
| `0` | No security issues found | Clean scan |
| `1` | Security issues detected | Vulnerabilities found |
| `2` | Execution error | Invalid path, permission denied |

---

## Configuration

XecureX supports configuration via file or CLI flags.

### Option 1: `xecurex.toml`

Create a `xecurex.toml` at the root of your repository:

```toml
[xecurex]
exclude_dirs = ["test_data", "fixtures", "migrations"]
min_severity = "medium"
use_ast = true
confidence_threshold = 0.5
max_file_size = 500000

[xecurex.include_extensions]
# Override default extensions (optional)
```

### Option 2: `pyproject.toml`

```toml
[tool.xecurex]
exclude_dirs = ["test_data", "fixtures"]
min_severity = "medium"
use_ast = true
confidence_threshold = 0.5
```

### Option 3: CLI Flags

```bash
# CLI flags override file configuration
xecurex . --min-severity high --no-ast --exclude vendor/
```

### Priority Order

1. CLI flags (highest priority)
2. `xecurex.toml`
3. `pyproject.toml`
4. Built-in defaults (lowest priority)

---

## Output

### Text Output

```
======================================================================
                    SECURITY AUDIT REPORT
======================================================================

  Files scanned:  42
  Lines scanned:  1583
  Files skipped:  0
  Scan duration:  0.12s

  Found 5 potential security issues:
    HIGH: 2  MEDIUM: 2  LOW: 1

  !!! HIGH Severity (2)
  --------------------------------------------------
    src/auth.py:15
      [CRED-001] Hardcoded password detected
      Confidence: [#########.]. (90%)
      Code: password = "supersecret123"

    src/database.py:42
      [INJECT-001] SQL query with string concatenation
      Confidence: [########..]. (85%)
      Code: cursor.execute("SELECT * FROM users WHERE id="

  !  MEDIUM Severity (2)
  --------------------------------------------------
    frontend/app.js:23
      [XSS-001] Dangerous innerHTML assignment
      Confidence: [########..]. (80%)
      Code: .innerHTML = userInput

    utils/crypto.py:8
      [CRYPTO-001] MD5 hash usage — weak, use SHA-256+
      Confidence: [#########..]. (90%)
      Code: hashlib.md5(data)

  i  LOW Severity (1)
  --------------------------------------------------
    src/config.py:5
      [HARDCODE-002] Insecure HTTP URL (should use HTTPS)
      Confidence: [######....]. (60%)
      Code: http://api.example.com/v1/users
```

### JSON Output

```bash
xecurex . --format json
```

```json
{
  "stats": {
    "files_scanned": 42,
    "lines_scanned": 1583,
    "files_skipped": 0,
    "errors": []
  },
  "findings": [
    {
      "file": "src/auth.py",
      "line": 15,
      "column": 0,
      "category": "Hardcoded Credentials",
      "description": "Hardcoded password detected",
      "severity": "HIGH",
      "rule_id": "CRED-001",
      "match": "password = \"supersecret123\"",
      "confidence": 0.9
    }
  ],
  "summary": {
    "total": 5,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "duration_seconds": 0.12
}
```

---

## JSON Schema

Each finding in the JSON output follows this structure:

```json
{
  "file": "string",          // Relative path to file
  "line": 1,                 // Line number (1-indexed)
  "column": 0,               // Column number (0-indexed)
  "category": "string",      // Vulnerability category
  "description": "string",   // Human-readable description
  "severity": "HIGH",        // HIGH | MEDIUM | LOW
  "rule_id": "CRED-001",     // Unique rule identifier
  "match": "string",         // Matched code snippet (max 80 chars)
  "confidence": 0.9          // Confidence score (0.0 – 1.0)
}
```

---

## Docker

### Build

```bash
docker build -t xecurex .
```

### Run

```bash
# Scan a local directory
docker run --rm -v /path/to/repo:/repo xecurex /repo

# JSON output
docker run --rm -v /path/to/repo:/repo xecurex /repo --format json

# Save report
docker run --rm -v /path/to/repo:/repo -v $(pwd):/out xecurex /repo --format json -o /out/report.json
```

### Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ src/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["xecurex"]
```

---

## Development

### Setup

```bash
git clone https://github.com/s1d9e/xecurex.git
cd xecurex
make install
```

### Available Commands

| Command | Description |
|---------|-------------|
| `make install` | Install package in dev mode |
| `make test` | Run tests with coverage |
| `make test-html` | Generate HTML coverage report |
| `make lint` | Run linter (ruff) |
| `make format` | Format code (ruff) |
| `make scan` | Scan current directory |
| `make clean` | Clean build artifacts |
| `make build` | Build distribution |

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
python -m pytest tests/test_rules/test_credentials.py -v

# Run with coverage report
python -m pytest tests/ --cov=src/xecurex --cov-report=term-missing

# Generate HTML coverage
make test-html
# Open htmlcov/index.html
```

### Code Quality

```bash
# Lint
make lint

# Format
make format

# Both
make lint && make format
```

---

## Project Structure

```
xecurex/
├── pyproject.toml                 # Package config (replaces setup.py)
├── Makefile                       # Dev commands
├── Dockerfile                     # Container support
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # Dev dependencies
│
├── src/xecurex/                   # Source package
│   ├── __init__.py                # Version: 2.0.0
│   ├── __main__.py                # python -m xecurex
│   ├── cli.py                     # CLI entry point (argparse)
│   ├── scanner.py                 # Scan orchestration engine
│   ├── reporter.py                # Text + JSON report generation
│   ├── models.py                  # Dataclasses: Finding, ScanResult
│   ├── config.py                  # Configuration management
│   │
│   ├── rules/                     # Security rules (modular)
│   │   ├── base.py                # Abstract Rule class + loader
│   │   ├── credentials.py         # CRED: hardcoded secrets
│   │   ├── injection.py           # INJECT: SQLi, cmd injection
│   │   ├── xss.py                 # XSS: cross-site scripting
│   │   ├── crypto.py              # CRYPTO: weak algorithms
│   │   ├── deserialization.py     # DESERN: unsafe deserialization
│   │   ├── path_traversal.py      # PATH: directory traversal
│   │   ├── data_exposure.py       # EXPOSE: sensitive data logging
│   │   ├── hardcoded.py           # HARDCODE: IPs, URLs
│   │   └── dependencies.py        # DEP: insecure libraries
│   │
│   └── analyzers/                 # Code analysis engines
│       ├── generic_analyzer.py    # Regex-based (all languages)
│       └── python_analyzer.py     # AST-based (Python native)
│
├── tests/                         # Test suite
│   ├── conftest.py                # Shared fixtures
│   ├── test_rules/                # Tests per rule category
│   │   ├── test_credentials.py
│   │   ├── test_injection.py
│   │   ├── test_xss.py
│   │   ├── test_crypto.py
│   │   └── test_deserialization.py
│   ├── test_analyzers/            # Analyzer tests
│   │   └── test_python_analyzer.py
│   ├── test_scanner.py            # Integration tests
│   └── test_cli.py                # CLI tests
│
├── .github/workflows/ci.yml      # GitHub Actions CI
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## Roadmap

- [ ] **v2.1** — SARIF output format (GitHub Security tab integration)
- [ ] **v2.2** — HTML report generation
- [ ] **v2.3** — Custom rule support (user-defined patterns)
- [ ] **v3.0** — AST parsing for JavaScript/TypeScript
- [ ] **v3.1** — Fix suggestions for each vulnerability
- [ ] **v3.2** — Scan caching (skip unchanged files)
- [ ] **v4.0** — Plugin system for community rules

---

## Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Guidelines

- Follow existing code style (ruff enforced)
- Add tests for new rules or features
- Update documentation if needed
- Keep commits atomic and well-described

---

## License

```
MIT License

Copyright (c) 2026 s1d9e

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Disclaimer

> **This tool is intended for authorized security testing only.**
> Always ensure you have explicit permission before scanning any code you do not own.
> The authors assume no liability for damages caused by misuse of this tool.

---

<p align="center">
  Built with Python by <a href="https://github.com/s1d9e">s1d9e</a>
  <br><br>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Made%20with-Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Made with Python">
</p>
