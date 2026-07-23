"""Generic regex-based analyzer for all languages."""

from __future__ import annotations

import re
from pathlib import Path

from xecurex.models import Finding
from xecurex.rules.base import Rule

# Patterns for comment detection per language
_COMMENT_PATTERNS = {
    ".py": re.compile(r"^\s*(?:#|'''|\"\"\")", re.MULTILINE),
    ".js": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".ts": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".jsx": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".tsx": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".java": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".php": re.compile(r"^\s*(?:/\*|//|#)", re.MULTILINE),
    ".rb": re.compile(r"^\s*(?:#|=begin)", re.MULTILINE),
    ".go": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".sh": re.compile(r"^\s*#", re.MULTILINE),
    ".cs": re.compile(r"^\s*(?:/\*|//)", re.MULTILINE),
    ".sql": re.compile(r"^\s*(?:--|/\*)", re.MULTILINE),
}


def strip_comments(content: str, filepath: str) -> str:
    """Remove comments from code to reduce false positives."""
    suffix = Path(filepath).suffix
    pattern = _COMMENT_PATTERNS.get(suffix)

    if not pattern:
        return content

    lines = content.split("\n")
    result = []
    in_block_comment = False

    for line in lines:
        stripped = line.strip()

        if suffix in (".py",):
            if stripped.startswith('"""') or stripped.startswith("'''"):
                if stripped.count(stripped[:3]) >= 2:
                    continue
                in_block_comment = not in_block_comment
                continue
            if in_block_comment:
                continue
            if stripped.startswith("#"):
                continue

        elif suffix in (".sh", ".rb", ".php", ".sql"):
            if stripped.startswith("#") or stripped.startswith("--"):
                continue

        else:
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith("/*"):
                if "*/" not in stripped:
                    in_block_comment = True
                continue
            if stripped.startswith("//"):
                continue

        result.append(line)

    return "\n".join(result)


class GenericAnalyzer:
    """Regex-based analyzer that works with any language."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def analyze(self, content: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        stripped = strip_comments(content, filepath)

        for rule in self.rules:
            if rule.language is not None:
                continue
            findings.extend(rule.check(stripped, filepath))

        return findings
