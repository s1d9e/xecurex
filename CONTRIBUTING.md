# Contributing to XecureX

Thanks for your interest in improving XecureX! PRs of all sizes are welcome.

## Development setup

```bash
git clone https://github.com/s1d9e/xecurex.git
cd xecurex
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before you push

```bash
make lint      # ruff check
make format    # ruff format
make test      # pytest with coverage (must stay green)
```

CI runs the same checks on Python 3.10–3.13.

## Adding a detection rule

1. Open the matching category in `src/xecurex/rules/` (create a new file
   only for a new category — then register it in `load_all_rules()`).
2. Add a `RulePattern` with:
   - a **unique** `rule_id` (`CATEGORY-NNN`, next free number — update
     `docs/RULES.md` to match),
   - a precise pattern (no `.*` soup — prefer lookbehinds over filters),
   - a realistic `severity` and an honest `confidence`
     (0.9 = you'd bet money, 0.6 = suspicious),
   - a description written for the developer who'll fix it.
3. Make sure the rule does **not** match:
   - code inside comments/docstrings (the engine handles this — don't
     re-implement it in the pattern),
   - placeholder values (`is_placeholder()` in `rules/base.py`).
4. Add tests in `tests/test_rules/`:
   - one test that the pattern fires on a realistic snippet,
   - one test that it stays quiet on the obvious false positive.
5. Update `docs/RULES.md` and bump the pattern count if needed.

## Adding a feature

- One feature per PR, with tests.
- CLI flags must default to `None` and only override the config file when
  explicitly provided.
- New output formats go through `src/xecurex/reporter.py`.

## Pull request checklist

- [ ] `make lint && make test` passes locally
- [ ] New rules documented in `docs/RULES.md`
- [ ] Tests added for new behavior
- [ ] README updated if user-facing

## Reporting bugs

Open an issue with:

- XecureX version (`xecurex --version`)
- OS and Python version
- A minimal code sample that reproduces the problem
- Command line used
