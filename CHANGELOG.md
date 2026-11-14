# Changelog

All notable changes to XecureX are documented in this file.

## [2.1.0] — 2026-11-14

### Added

- **SARIF 2.1.0 output** (`--format sarif`) — upload results to GitHub
  Code Scanning with `github/codeql-action/upload-sarif`.
- **Baseline files** (`--baseline FILE`) — suppress known findings from a
  previous JSON report or a `file:line:rule_id` text file; adopt XecureX
  on legacy codebases without fixing everything at once.
- **`.xecurexignore`** — gitignore-style exclusions at the repository root.
- **pre-commit hook** (`.pre-commit-hooks.yaml`).
- `--ast / --no-ast` replaces the old `--no-ast`-only flag; AST can now be
  re-enabled from the CLI even when the config file disables it.
- Unique `rule_id` for every detection pattern (66 regex rules + AST rules).

### Fixed

- Comment stripping no longer shifts line numbers: comments are blanked in
  place, preserving lines **and** columns.
- Inline comments, multi-line block comments and Python docstrings are now
  detected correctly (quote-aware, column-aware).
- CLI flags no longer override `xecurex.toml` unless explicitly provided.
- AST and regex findings on the same location are deduplicated (no more
  double reports for `os.system()`, `password = "…"`, `hashlib.md5()`…).
- Path exclusions match path components/globs instead of raw substrings:
  `build` no longer excludes `mybuild/`, `.git` no longer excludes `.github/`.
- Placeholder values (`your_password`, `${API_KEY}`, `<YOUR_KEY>`, …) are
  no longer reported as hardcoded secrets.
- `load_config()` continues to `pyproject.toml` when `xecurex.toml` has no
  xecurex section, and warns on invalid TOML instead of failing silently.
- `python -m xecurex` now exits with the proper status code (was always 0).
- JSON/SARIF files are written as UTF-8.
- Version-like quads on lines mentioning `version`/`release` are not
  reported as hardcoded IPs; public IPs embedded in URLs are no longer
  double-reported.

### Changed

- `XSS-007`/`XSS-008` require a jQuery-style receiver (`$(` / `jQuery(`)
  so Python `list.append()` calls are not flagged.
- Test suite: 68 → 197 tests, 93% coverage.

## [2.0.0] — 2026-10-23

- Multi-language scanning (10 languages), AST analysis for Python,
  66+ detection patterns across 9 categories, JSON output, Docker,
  configuration via `xecurex.toml`.
