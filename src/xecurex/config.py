"""Configuration management for XecureX."""

from __future__ import annotations

import contextlib
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
        return any(excluded in path_str for excluded in self.exclude_dirs)

    def should_include(self, suffix: str) -> bool:
        return suffix in self.include_extensions

    def passes_severity_filter(self, severity: Severity) -> bool:
        return SEVERITY_ORDER.get(severity, 2) <= SEVERITY_ORDER.get(self.min_severity, 2)


def load_config(repo_path: Path) -> Config:
    config = Config()

    for name in ("xecurex.toml", "pyproject.toml"):
        config_path = repo_path / name
        if config_path.exists():
            try:
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)
                xec = data.get("tool", {}).get("xecurex", {})
                if not xec:
                    xec = data.get("xecurex", {})
                _apply_config(config, xec)
                break
            except Exception:
                pass

    return config


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
