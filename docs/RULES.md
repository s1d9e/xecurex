# Rules Reference

XecureX uses **66+ detection patterns** across **9 vulnerability categories**.

Each finding includes a unique `rule_id`, severity level, and confidence score.

## Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| **HIGH** | 🔴 | Critical risk — likely exploitable |
| **MEDIUM** | 🟡 | Moderate risk — potential vulnerability |
| **LOW** | 🟢 | Low risk — best practice violation |

## CRED — Hardcoded Credentials

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

**What it catches:**
- `password = "secret123"`
- `api_key = "ak_live_..."`
- `aws_access_key_id = "AKIA..."`
- `private_key = "-----BEGIN RSA PRIVATE KEY-----"`

**What it ignores:**
- References to environment variables (`os.environ["..."]`)
- Short strings (< 8 chars)
- Code in comments

---

## INJECT — Injection Vulnerabilities

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
| `INJECT-011` | `setTimeout` with string (JS) | MEDIUM | 70% |
| `INJECT-012` | `setInterval` with string (JS) | MEDIUM | 70% |

**What it catches:**
- `os.system("ls")`
- `cursor.execute("SELECT * FROM users WHERE id=" + user_id)`
- `eval(user_input)`
- `subprocess.run("ls", shell=True)`

---

## XSS — Cross-Site Scripting

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `XSS-001` | Dangerous `innerHTML` assignment | MEDIUM | 80% |
| `XSS-002` | `document.write()` usage | MEDIUM | 75% |
| `XSS-003` | React `dangerouslySetInnerHTML` | MEDIUM | 80% |
| `XSS-004` | Dangerous `outerHTML` assignment | MEDIUM | 80% |
| `XSS-005` | `document.writeln()` usage | MEDIUM | 75% |
| `XSS-006` | `insertAdjacentHTML` | MEDIUM | 80% |
| `XSS-007` | jQuery `.html()` with concatenation | MEDIUM | 70% |
| `XSS-008` | jQuery `.append()` with concatenation | MEDIUM | 65% |

**What it catches:**
- `element.innerHTML = userInput`
- `document.write(untrusted)`
- `<div dangerouslySetInnerHTML={{__html: data}} />`

---

## CRYPTO — Weak Cryptography

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `CRYPTO-001` | MD5 hash usage | MEDIUM | 90% |
| `CRYPTO-002` | SHA-1 hash usage | MEDIUM | 90% |
| `CRYPTO-003` | Weak hash via `hashlib.new()` | MEDIUM | 90% |
| `CRYPTO-004` | Weak symmetric cipher (DES, Blowfish, RC4) | MEDIUM | 85% |
| `CRYPTO-005` | `.md5()` digest usage | MEDIUM | 80% |
| `CRYPTO-006` | `.sha1()` digest usage | MEDIUM | 80% |
| `CRYPTO-007` | `Math.random()` (not crypto-safe) | LOW | 60% |

**What it catches:**
- `hashlib.md5(data)`
- `hashlib.sha1(data)`
- `hashlib.new("md5", data)`
- `Crypto.Cipher.DES.new(key)`

---

## DESERN — Insecure Deserialization

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `DESERN-001` | `pickle.load()` / `pickle.loads()` | HIGH | 95% |
| `DESERN-002` | `yaml.load()` without Loader | HIGH | 90% |
| `DESERN-003` | `yaml.unsafe_load()` | HIGH | 95% |
| `DESERN-004` | `marshal.loads()` | HIGH | 90% |
| `DESERN-005` | `shelve.open()` (uses pickle) | MEDIUM | 80% |
| `DESERN-006` | `jsonpickle.decode()` | HIGH | 85% |
| `DESERN-007` | PHP `unserialize()` | HIGH | 90% |
| `DESERN-008` | PHP serialize/unserialize pattern | MEDIUM | 60% |

**What it catches:**
- `pickle.load(file)` — arbitrary code execution risk
- `yaml.load(data)` — use `yaml.safe_load()` instead
- `marshal.loads(data)` — arbitrary code execution risk

---

## PATH — Path Traversal

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `PATH-001` | Dynamic file path in `open()` | MEDIUM | 70% |
| `PATH-002` | `../` pattern detected | MEDIUM | 50% |
| `PATH-003` | `..\` pattern detected (Windows) | MEDIUM | 50% |
| `PATH-004` | `readfile()` usage | MEDIUM | 60% |
| `PATH-005` | Node.js `readFileSync` + dynamic | MEDIUM | 70% |
| `PATH-006` | Node.js `fs.readFile` + dynamic | MEDIUM | 70% |
| `PATH-007` | `path.join` starting with `..` | MEDIUM | 75% |

---

## EXPOSE — Sensitive Data Exposure

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `EXPOSE-001` | Sensitive data in `console.log()` | LOW | 70% |
| `EXPOSE-002` | Sensitive data in `print()` | LOW | 65% |
| `EXPOSE-003` | Sensitive data in logging call | LOW | 60% |
| `EXPOSE-004` | Sensitive data in `console.warn()` | LOW | 65% |
| `EXPOSE-005` | Sensitive data in `console.error()` | LOW | 60% |
| `EXPOSE-006` | Sensitive data in `sys.stdout.write()` | LOW | 65% |

---

## HARDCODE — Hardcoded IP/URL

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `HARDCODE-001` | Hardcoded IP address | LOW | 50% |
| `HARDCODE-002` | Insecure HTTP URL | LOW | 60% |

**Filters:** Private IPs (10.x, 192.168.x, 127.x) and version-like strings (1.0.0.1) are excluded.

---

## DEP — Insecure Dependencies

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `DEP-001` | Node.js `crypto` module | LOW | 40% |
| `DEP-002` | JWT library usage | LOW | 50% |
| `DEP-003` | `eval` npm package | MEDIUM | 80% |
| `DEP-004` | `telnetlib` (unencrypted) | MEDIUM | 80% |
| `DEP-005` | `telnetlib` import | MEDIUM | 80% |

---

## AST Rules (Python Only)

Python files are analyzed with the native `ast` module in addition to regex. These rules provide higher precision:

| Rule ID | Description | Severity | Confidence |
|---------|-------------|----------|------------|
| `INJECT-AST-001` | `os.system()` via AST | HIGH | 95% |
| `INJECT-AST-002` | `os.popen()` via AST | HIGH | 95% |
| `INJECT-AST-003` | `eval()` via AST | HIGH | 95% |
| `INJECT-AST-004` | `exec()` via AST | HIGH | 95% |
| `INJECT-AST-007` | `subprocess` with `shell=True` via AST | HIGH | 95% |
| `DESERN-AST-001` | `pickle.load()` via AST | HIGH | 95% |
| `DESERN-AST-002` | `pickle.loads()` via AST | HIGH | 95% |
| `DESERN-AST-003` | `yaml.load()` via AST | HIGH | 90% |
| `CRYPTO-AST-001` | `hashlib.md5` via AST | MEDIUM | 90% |
| `CRYPTO-AST-002` | `hashlib.sha1` via AST | MEDIUM | 90% |
| `CRED-AST-001` | Hardcoded credential assignment via AST | HIGH | 85% |
| `DEP-AST-010` | Dangerous import via AST | MEDIUM | 70% |
