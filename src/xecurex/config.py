"""Configuration management for XecureX."""

from __future__ import annotations

import contextlib
import fnmatch
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib

from xecurex.models import Severity

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "vendor",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "coverage",
        "htmlcov",
        ".eggs",
        "*.egg-info",
    }
)

DEFAULT_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".php",
        ".rb",
        ".go",
        ".sh",
        ".cs",
        ".sql",
    }
)

SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass
class Config:
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    include_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    min_severity: Severity = Severity.LOW
    use_ast: bool = True
    confidence_threshold: float = 0.3
    max_file_size: int = 1_000_000  # 1MB

    def should_exclude(self, path_str: str) -> bool:
        """Return True when the path matches an exclusion pattern.

        Patterns match individual path components (fnmatch globs such as
        ``*.egg-info``), full relative paths, or path prefixes. A pattern
        never matches by bare substring, so ``build`` does not exclude
        ``mybuild/`` and ``.git`` does not exclude ``.github/``.
        """
        parts = Path(path_str).parts
        for excluded in self.exclude_dirs:
            pattern = excluded.rstrip("/")
            if not pattern:
                continue
            if any(fnmatch.fnmatch(part, pattern) for part in parts):
                return True
            if path_str == pattern or path_str.startswith(pattern + "/"):
                return True
            if fnmatch.fnmatch(path_str, pattern):
                return True
        return False

    def should_include(self, suffix: str) -> bool:
        return suffix in self.include_extensions

    def passes_severity_filter(self, severity: Severity) -> bool:
        return SEVERITY_ORDER.get(severity, 2) <= SEVERITY_ORDER.get(self.min_severity, 2)


def load_config(repo_path: Path) -> Config:
    """Load configuration from ``xecurex.toml`` or ``pyproject.toml``.

    The first file that contains an xecurex section wins. A file without
    such section (or an invalid TOML file) does not stop the search.
    """
    config = Config()

    for name in ("xecurex.toml", "pyproject.toml"):
        config_path = repo_path / name
        if not config_path.exists():
            continue
        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            print(f"xecurex: invalid TOML in {config_path}: {exc}", file=sys.stderr)
            continue
        except OSError as exc:
            print(f"xecurex: cannot read {config_path}: {exc}", file=sys.stderr)
            continue

        xec = data.get("tool", {}).get("xecurex", {})
        if not xec:
            xec = data.get("xecurex", {})
        if not xec:
            continue

        _apply_config(config, xec)
        break

    _load_ignore_file(repo_path, config)

    return config


def _load_ignore_file(repo_path: Path, config: Config) -> None:
    """Load ``.xecurexignore`` patterns (one per line, ``#`` for comments).

    Patterns use the same syntax as ``exclude_dirs``: fnmatch globs matched
    against path components or path prefixes (``tests``, ``*.min.js``,
    ``src/generated``).
    """
    ignore_path = repo_path / ".xecurexignore"
    if not ignore_path.is_file():
        return
    try:
        lines = ignore_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"xecurex: cannot read {ignore_path}: {exc}", file=sys.stderr)
        return

    for line in lines:
        # Normalize gitignore-style patterns: strip whitespace and slashes.
        pattern = line.strip().strip("/")
        if not pattern or pattern.startswith("#"):
            continue
        if pattern not in config.exclude_dirs:
            config.exclude_dirs.append(pattern)


def _apply_config(config: Config, data: dict[str, Any]) -> None:
    if "exclude_dirs" in data:
        config.exclude_dirs = list(set(config.exclude_dirs) | set(data["exclude_dirs"]))

    if "include_extensions" in data:
        config.include_extensions = data["include_extensions"]

    if "min_severity" in data:
        with contextlib.suppress(ValueError):
            config.min_severity = Severity(data["min_severity"].upper())

    if "use_ast" in data:
        config.use_ast = bool(data["use_ast"])

    if "confidence_threshold" in data:
        config.confidence_threshold = float(data["confidence_threshold"])

    if "max_file_size" in data:
        config.max_file_size = int(data["max_file_size"])
