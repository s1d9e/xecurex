# XecureX - Security Audit Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue?style=flat&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange?style=flat" alt="Version">
</p>

XecureX is a powerful open-source security audit tool designed for red team operations. It analyzes repositories to detect common security vulnerabilities and helps developers secure their code before deployment.

## Features

- **Hardcoded Credentials** - Detects passwords, API keys, secrets, tokens hardcoded in source code
- **SQL Injection** - Identifies string concatenation in SQL queries that could lead to injection attacks
- **Command Injection** - Finds dangerous system calls (os.system, eval, shell=True, subprocess)
- **Path Traversal** - Detects dynamic file paths that could be exploited
- **XSS Vulnerabilities** - Identifies unsafe DOM manipulation (innerHTML, document.write)
- **Weak Cryptography** - Finds usage of weak hash algorithms (MD5, SHA1)
- **Insecure Deserialization** - Detects unsafe deserialization patterns (pickle, yaml.load)
- **Sensitive Data Exposure** - Finds secrets logged to console or printed

## Installation

```bash
# Clone the repository
git clone https://github.com/s1d9e/xecurex.git
cd xecurex

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic scan
python src/main.py /path/to/repository

# JSON output
python src/main.py /path/to/repository --format json

# Save results to file
python src/main.py /path/to/repository -o results.json

# Exclude additional directories
python src/main.py /path/to/repository --exclude test_data cache
```

## Supported Languages

| Language | Extensions |
|----------|------------|
| Python | .py |
| JavaScript/TypeScript | .js, .ts, .jsx, .tsx |
| Java | .java |
| PHP | .php |
| Ruby | .rb |
| Go | .go |
| Shell | .sh |
| C# | .cs |
| SQL | .sql |

## Severity Levels

| Severity | Color | Categories |
|----------|-------|------------|
| HIGH | 🔴 | Hardcoded Credentials, Command Injection, SQL Injection, Insecure Deserialization |
| MEDIUM | 🟡 | XSS Vulnerabilities, Path Traversal, Weak Crypto |
| LOW | 🟢 | Sensitive Data Exposure, Hardcoded IP/URL |

## Example Output

```
======================================================================
                    SECURITY AUDIT REPORT
======================================================================

📊 Statistics:
   Files scanned: 42
   Lines scanned: 1583

[!] Found 5 potential security issues:

🔴 HIGH Severity (2)
--------------------------------------------------
  📁 src/auth.py:15
     [Hardcoded Credentials] Hardcoded password detected

  📁 src/database.py:42
     [SQL Injection] SQL query with string concatenation

🟡 MEDIUM Severity (2)
--------------------------------------------------
  📁 frontend/app.js:23
     [XSS Vulnerabilities] Dangerous innerHTML assignment

  📁 utils/crypto.py:8
     [Weak Crypto] MD5 hash usage - weak cryptographic

🟢 LOW Severity (1)
--------------------------------------------------
  📁 src/config.py:5
     [Hardcoded IP/URL] Hardcoded IP address
```

## Testing

```bash
# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for authorized security testing only. Always ensure you have explicit permission before scanning any repository that you do not own. The authors assume no liability for any damages caused by misuse of this tool.

---

<p align="center">Made with 🔒 by s1d9e</p>
