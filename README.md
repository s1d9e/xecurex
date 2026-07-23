# XecureX

Open-source security audit tool for source code. Detects hardcoded secrets, SQL injection, XSS, command injection, and more.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat)](https://github.com/s1d9e/xecurex/actions)

## Features

- **Hardcoded Credentials** — passwords, API keys, tokens, AWS credentials
- **SQL Injection** — string concatenation, f-string queries
- **Command Injection** — `os.system()`, `eval()`, `subprocess(shell=True)`
- **XSS** — `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`
- **Weak Cryptography** — MD5, SHA-1 usage
- **Insecure Deserialization** — `pickle`, `yaml.load()`, `marshal`
- **Path Traversal** — dynamic file paths, `../` patterns
- **Sensitive Data Exposure** — secrets logged to console
- **Hardcoded IPs/URLs** — insecure HTTP, hardcoded addresses

## Detection Engine

| Language | Method | Precision |
|----------|--------|-----------|
| Python | AST parsing + Regex | High |
| JavaScript/TypeScript | Regex (improved) | Medium |
| Java, Go, PHP, Ruby, C#, Shell, SQL | Regex (improved) | Medium |

## Installation

```bash
git clone https://github.com/s1d9e/xecurex.git
cd xecurex
pip install -e ".[dev]"
```

## Usage

```bash
# Basic scan
xecurex /path/to/repo

# JSON output
xecurex /path/to/repo --format json --output report.json

# Only HIGH severity
xecurex /path/to/repo --min-severity high

# Exclude directories
xecurex /path/to/repo --exclude tests/ docs/

# Verbose mode
xecurex /path/to/repo --verbose

# Disable AST (regex only)
xecurex /path/to/repo --no-ast
```

## CLI Options

```
xecurex [-h] [--format {text,json}] [-o OUTPUT]
        [--min-severity {low,medium,high}] [--exclude [EXCLUDE ...]]
        [--no-ast] [--no-config] [--min-confidence MIN_CONFIDENCE]
        [-v] [--version]
        path
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format` | Output format (`text` or `json`) | `text` |
| `-o, --output` | Save results to file | stdout |
| `--min-severity` | Minimum severity to report | `low` |
| `--exclude` | Additional directories to exclude | — |
| `--no-ast` | Disable Python AST analysis | AST enabled |
| `--min-confidence` | Minimum confidence threshold (0.0–1.0) | `0.3` |
| `-v, --verbose` | Show scan progress | off |

## Configuration

Create a `xecurex.toml` at the root of your repository:

```toml
[xecurex]
exclude_dirs = ["test_data", "fixtures"]
min_severity = "medium"
use_ast = true
confidence_threshold = 0.5
max_file_size = 500000
```

Or add to `pyproject.toml`:

```toml
[tool.xecurex]
exclude_dirs = ["test_data", "fixtures"]
min_severity = "medium"
```

## Output Example

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
      [XSS-001] Dangerous innerHTML assignment — XSS risk
      Confidence: [########..]. (80%)
      Code: .innerHTML = userInput

  i  LOW Severity (1)
  --------------------------------------------------
    src/config.py:5
      [HARDCODE-001] Insecure HTTP URL (should use HTTPS)
      Confidence: [######....]. (60%)
      Code: http://api.example.com/v1/users
```

## Development

```bash
# Install dev dependencies
make install

# Run tests
make test

# Run linter
make lint

# Format code
make format

# Scan the project itself
make scan
```

## Docker

```bash
docker build -t xecurex .
docker run --rm -v /path/to/repo:/repo xecurex /repo
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No security issues found |
| `1` | Security issues detected |
| `2` | Execution error |

## Project Structure

```
src/xecurex/
├── __init__.py           # Version info
├── __main__.py           # python -m xecurex
├── cli.py                # CLI entry point
├── scanner.py            # Scan orchestration
├── reporter.py           # Text + JSON reports
├── models.py             # Dataclasses (Finding, ScanResult)
├── config.py             # Configuration management
├── rules/                # Security rules (modular)
│   ├── base.py           # Abstract Rule class
│   ├── credentials.py    # Hardcoded secrets
│   ├── injection.py      # SQLi, command injection
│   ├── xss.py            # Cross-site scripting
│   ├── crypto.py         # Weak cryptography
│   ├── deserialization.py # Unsafe deserialization
│   ├── path_traversal.py # Directory traversal
│   ├── data_exposure.py  # Sensitive data logging
│   ├── hardcoded.py      # IPs, URLs
│   └── dependencies.py   # Insecure libraries
└── analyzers/            # Code analysis engines
    ├── generic_analyzer.py   # Regex-based (all languages)
    └── python_analyzer.py    # AST-based (Python)
```

## License

MIT License — see [LICENSE](LICENSE)

## Disclaimer

This tool is intended for authorized security testing only. Always ensure you have explicit permission before scanning any code you do not own.

---

Made by s1d9e
