<p align="center">
  <img src="https://img.shields.io/badge/XecureX-2.1.0-ff4444?style=for-the-badge&logo=shield&logoColor=white" alt="XecureX">
</p>

<h1 align="center">⚡ XecureX</h1>

<p align="center">
  <strong>Open-source security audit for source code — secrets, injection, XSS, weak crypto & more</strong><br>
  One command. Ten languages. Zero config. Findings you can actually trust.
</p>

<p align="center">
  <a href="https://github.com/s1d9e/xecurex/actions/workflows/ci.yml"><img src="https://github.com/s1d9e/xecurex/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/coverage-93%25-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/tests-197%20passed-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Python-3.10%E2%80%933.13-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00FF00?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="#-demo">Demo</a> •
  <a href="#-why-xecurex">Why XecureX</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-github-code-scanning">GitHub Integration</a> •
  <a href="#-cli">CLI</a> •
  <a href="docs/RULES.md">All 66 Rules</a> •
  <a href="#-roadmap">Roadmap</a>
</p>

---

## 🎬 Demo

```console
$ xecurex .

======================================================================
                    SECURITY AUDIT REPORT
======================================================================

  Files scanned:  41
  Lines scanned:  3508
  Scan duration:  0.35s

  Found 3 potential security issues:
    HIGH: 1  MEDIUM: 2  LOW: 0

  !!! HIGH Severity (1)
  --------------------------------------------------
    tests/test_rules/test_deserialization.py:37
      [DESERN-007] PHP unserialize — insecure deserialization
      Confidence: [#########.] (90%)
      Code: unserialize(

  !  MEDIUM Severity (2)
  --------------------------------------------------
    tests/test_rules/test_path_traversal.py:26
      [PATH-004] readfile() with potential path traversal
      Confidence: [######....] (60%)
      Code: readfile(
```

> Real output from scanning XecureX itself: **93 findings → 3**, and all 3
> are true positives inside test fixtures that deliberately contain
> vulnerable code.

---

## 🎯 Why XecureX

Most security scanners force a trade-off: **precise but heavy** (Semgrep,
CodeQL — steep learning curve, thousands of rules you'll never read) or
**light but noisy** (raw grep, naive linters — 93 false positives).

XecureX sits in the middle, on purpose:

| | |
|---|---|
| 🔍 **Hybrid analysis** | Python `ast` for precision + cross-language regex for coverage — duplicates merged automatically |
| 🎚 **Confidence scoring** | Every finding rated 0.0–1.0, so you triage what matters first |
| 🧹 **Noise control** | Placeholder detection (`your_password`, `${API_KEY}`), comment/docstring awareness, `.xecurexignore`, baselines |
| 🌍 **10 languages** | Python, JS/TS, Java, Go, PHP, Ruby, C#, Shell, SQL |
| 📦 **1 dependency** | `colorama`. That's it. No daemon, no server, no telemetry |
| 📖 **Readable rules** | 66 rules, one file per category, plain regex you can understand and extend in minutes |
| 🚀 **CI-native** | Exit codes, JSON, **SARIF** (GitHub Code Scanning), baseline files, pre-commit hook |

**Honest limits:** XecureX has no dataflow/taint analysis and won't match
Semgrep's rule ecosystem. It's the audit tool you can read, modify and
deploy in an hour — not an enterprise platform.

---

## ⚔️ Comparison

| | **XecureX** | Bandit | Semgrep | Gitleaks | Trivy |
|---|---|---|---|---|---|
| Primary focus | Full code audit (9 categories) | Python lint | Semantic multi-lang | Secrets in **git history** | CVEs / deps / containers |
| Languages | **10** | 1 (Python) | 20+ | any (regex) | any |
| Hardcoded secrets | ✅ | ✅ | ✅ | ✅ | ✅ |
| Injection / XSS / deser. | ✅ | ✅ (Python) | ✅ | ❌ | ❌ |
| AST analysis | ✅ (Python) | ✅ | ✅ (many) | ❌ | ❌ |
| Confidence scoring | ✅ | ❌ | ❌ | ❌ | ❌ |
| SARIF output | ✅ | ✅ | ✅ | ✅ | ✅ |
| Baseline / ignore | ✅ | partial | ✅ | ✅ | ✅ |
| Setup | `pip install`, 1 dep | pip | binary or pip | binary | binary |
| Rules readable in | **one afternoon** | one file | weeks | one file | weeks |

**Pick XecureX when** you want a fast, explainable, multi-language audit
with low noise. **Pick Semgrep/CodeQL when** you need deep dataflow analysis.
**Pick Gitleaks when** you must scan commit history.

---

## 🚀 Quick Start

```bash
# Install from GitHub
pip install git+https://github.com/s1d9e/xecurex.git

# Scan a repository
xecurex /path/to/repo

# Machine-readable output
xecurex /path/to/repo --format json -o report.json
xecurex /path/to/repo --format sarif -o xecurex.sarif   # GitHub Code Scanning

# Only HIGH severity, ignore some paths
xecurex /path/to/repo --min-severity high --exclude tests/ docs/

# With Docker
docker build -t xecurex . && docker run --rm -v "$PWD":/repo xecurex /repo
```

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/s1d9e/xecurex
    rev: v2.1.0
    hooks:
      - id: xecurex
```

```bash
pre-commit install
pre-commit run xecurex --all-files
```

---

## 🔗 GitHub Code Scanning

XecureX emits **SARIF 2.1.0** — results appear as annotations on your PRs:

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  xecurex:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/s1d9e/xecurex.git
      - run: xecurex . --format sarif -o xecurex.sarif
        continue-on-error: true   # exit code 1 = findings
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: xecurex.sarif
```

---

## 📋 Features

| Capability | Details |
|------------|---------|
| **AST-based analysis** | Python `ast` module — precise, context-aware, deduplicated vs regex |
| **66+ detection patterns** | 9 categories: CRED, INJECT, XSS, CRYPTO, DESERN, PATH, EXPOSE, HARDCODE, DEP |
| **Placeholder filtering** | `your_password`, `${API_KEY}`, `<YOUR_KEY>`, `changeme`… never reported |
| **Comment-aware** | Comments, docstrings and inline code in strings are ignored |
| **Confidence scoring** | Each finding rated 0.0–1.0 |
| **Multi-language** | Python, JS, TS, Java, Go, PHP, Ruby, C#, Shell, SQL |
| **3 output formats** | Text, JSON, **SARIF 2.1.0** |
| **CI/CD ready** | Exit codes, baseline files, pre-commit hook, Docker, GitHub Actions |
| **Configurable** | `xecurex.toml`, `.xecurexignore`, severity/confidence filters |

---

## 📋 CLI

```
xecurex [OPTIONS] PATH
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format {text,json,sarif}` | Output format | `text` |
| `-o, --output FILE` | Save to file (UTF-8) | stdout |
| `--baseline FILE` | Suppress findings from a previous report | — |
| `--min-severity {low,medium,high}` | Filter by severity | config (`low`) |
| `--exclude DIR ...` | Exclude paths (globs like `*.min.js`) | — |
| `--ast / --no-ast` | Enable/disable Python AST analysis | config (`on`) |
| `--no-config` | Ignore `xecurex.toml` / `pyproject.toml` / `.xecurexignore` | off |
| `--min-confidence FLOAT` | Min confidence 0.0–1.0 | config (`0.3`) |
| `-v, --verbose` | Show scan progress | off |
| `--version` | Show version | — |

Flags only override the configuration file when explicitly provided.

| Exit Code | Meaning |
|-----------|---------|
| `0` | No issues found |
| `1` | Issues detected |
| `2` | Error |

---

## 📊 Output

<details>
<summary>Text report</summary>

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
      Confidence: [#########.] (90%)
      Code: password = "supersecret123"

  !  MEDIUM Severity (2)
  --------------------------------------------------
    frontend/app.js:23
      [XSS-001] Dangerous innerHTML assignment
      Confidence: [########..] (80%)
      Code: .innerHTML = userInput
```

</details>

<details>
<summary>JSON report</summary>

```json
{
  "stats": { "files_scanned": 42, "lines_scanned": 1583 },
  "findings": [
    {
      "file": "src/auth.py",
      "line": 15,
      "column": 0,
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

</details>

<details>
<summary>SARIF report (GitHub Code Scanning)</summary>

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "XecureX",
          "version": "2.1.0",
          "rules": [
            {
              "id": "CRED-001",
              "shortDescription": { "text": "Hardcoded password detected" },
              "defaultConfiguration": { "level": "error" },
              "properties": { "security-severity": "8.5" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CRED-001",
          "level": "error",
          "message": { "text": "Hardcoded password detected" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/auth.py" },
                "region": { "startLine": 15, "startColumn": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

</details>

---

## ⚙️ Configuration

Create `xecurex.toml` or add to `pyproject.toml`:

```toml
[xecurex]
exclude_dirs = ["test_data", "fixtures"]
min_severity = "medium"
use_ast = true
confidence_threshold = 0.5
```

- `xecurex.toml` is read first, then `pyproject.toml` (`[tool.xecurex]`).
  A file without an xecurex section — or invalid TOML — does not stop the
  search; a warning is printed to stderr.
- CLI flags override file configuration.
- Exclusion patterns match whole path components or path prefixes with
  fnmatch globs: `build` never excludes `mybuild/`, `.git` never excludes
  `.github/`.

### `.xecurexignore`

Gitignore-style file at the repository root — same pattern syntax as
`exclude_dirs`:

```
# fixtures and generated code
fixtures
tests/
*.generated.js
```

### Baseline

Adopt XecureX on an existing codebase without fixing everything at once:

```bash
# 1. Record current findings
xecurex . --format json -o baseline.json

# 2. Later scans only report NEW issues (exit 0 = clean)
xecurex . --baseline baseline.json
```

A plain-text format works too — one entry per line:

```
src/legacy/auth.py:42:CRED-001
# comments and blank lines are ignored
```

---

## 🐳 Docker

```bash
docker build -t xecurex .
docker run --rm -v /path/to/repo:/repo xecurex /repo
```

---

## 🛠 Development

```bash
make install    # Install dev dependencies
make test       # Run tests with coverage (197 tests, 93%)
make lint       # Lint (ruff)
make format     # Format (ruff)
make scan       # Scan XecureX itself
```

### Project structure

```
src/xecurex/
├── cli.py                  # CLI entry point
├── scanner.py              # Scan orchestration + dedup
├── reporter.py             # Text + JSON + SARIF reports
├── models.py               # Finding, ScanResult dataclasses
├── config.py               # Config, .xecurexignore, exclusions
├── rules/                  # 9 rule categories (66+ patterns)
│   ├── base.py             # Rule engine, placeholders, comments
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

## 🗺 Roadmap

- [x] SARIF 2.1.0 output (GitHub Code Scanning)
- [x] `.xecurexignore` + baseline files
- [x] pre-commit hook
- [ ] **Diff mode** — scan only files changed in a PR
- [ ] **Custom rules in YAML** — write your own without touching Python
- [ ] **Git history secret scanning**
- [ ] **PyPI release** (`pip install xecurex`)
- [ ] VS Code extension

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🤝 Contributing

Fork → Branch → Commit → Push → PR. Add tests for new rules, run
`make lint && make test` before submitting. Full guide in
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## ⭐ Star History

<a href="https://github.com/s1d9e/xecurex">
  <img src="https://api.star-history.com/svg?repos=s1d9e/xecurex&type=Date" alt="Star History Chart" width="100%">
</a>

---

## 📄 License

MIT — see [LICENSE](LICENSE)

## ⚠️ Disclaimer

> This tool is for authorized security testing only. Always ensure you have
> permission before scanning code you do not own.

---

<p align="center">
  Built by <a href="https://github.com/s1d9e">s1d9e</a> •
  <a href="https://github.com/s1d9e/xecurex/stargazers">⭐ Star the repo</a> if XecureX saved you time
</p>
