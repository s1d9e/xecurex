"""Abstract base class for security rules."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from xecurex.models import Finding, Severity

# Comment tokens per language suffix.
_COMMENT_TOKENS: dict[str, tuple[str, ...]] = {
    ".py": ("#",),
    ".sh": ("#",),
    ".rb": ("#",),
    ".php": ("#", "//", "/*"),
    ".sql": ("--", "#", "/*"),
    ".js": ("//", "/*"),
    ".ts": ("//", "/*"),
    ".jsx": ("//", "/*"),
    ".tsx": ("//", "/*"),
    ".java": ("//", "/*"),
    ".go": ("//", "/*"),
    ".cs": ("//", "/*"),
}
_DEFAULT_COMMENT_TOKENS = ("#", "//", "/*")

# Values that look like placeholders rather than real secrets.
_PLACEHOLDER_VALUES = frozenset(
    {
        "example",
        "changeme",
        "change_me",
        "change-me",
        "your_password",
        "your-secret",
        "your_key",
        "your-key",
        "your_token",
        "your-token",
        "your_api_key",
        "xxx",
        "xxxx",
        "todo",
        "fixme",
        "redacted",
        "placeholder",
        "dummy",
        "sample",
        "test",
        "test123",
        "none",
        "null",
        "undefined",
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "value",
        "here",
        "insert_here",
        "insert_value",
        "replace_me",
        "replace_it",
        "change_it",
        "123456",
        "12345678",
        "abcdef",
        "qwerty",
        "abc123",
        "letmein",
        "welcome",
    }
)

_PLACEHOLDER_PATTERNS = (
    re.compile(r"^(?:your|insert|put|enter|replace|change|the)[-_].+", re.IGNORECASE),
    re.compile(r"^<[^<>]*>$"),
    re.compile(r"^\{[^{}]*\}$"),
    re.compile(r"^\$\{[^}]*\}$"),
    re.compile(r"^%[sd]$"),
)


def is_placeholder(value: str) -> bool:
    """Return True when a value looks like a placeholder, not a real secret."""
    v = value.strip()
    if not v:
        return True
    if v.lower() in _PLACEHOLDER_VALUES:
        return True
    if len(v) <= 4 and set(v) <= {"x", "*", "-", "."}:
        return True
    return any(p.match(v) for p in _PLACEHOLDER_PATTERNS)


def _is_in_comment(line_text: str, col: int, tokens: tuple[str, ...]) -> bool:
    """Return True when position ``col`` of ``line_text`` lies in a comment."""
    stripped = line_text.lstrip()
    if stripped.startswith(tokens):
        return True
    return _comment_token_before(line_text[:col], tokens)


def _comment_token_before(prefix: str, tokens: tuple[str, ...]) -> bool:
    """Scan ``prefix`` for a comment token outside of string literals."""
    quote: str | None = None
    i = 0
    n = len(prefix)
    while i < n:
        ch = prefix[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            i += 1
            continue
        for tok in tokens:
            if prefix.startswith(tok, i):
                return True
        i += 1
    return False


@dataclass
class RulePattern:
    pattern: str
    description: str
    severity: Severity
    confidence: float = 1.0
    flags: int = re.IGNORECASE | re.MULTILINE
    rule_id: str | None = None
    _compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, self.flags)


class Rule(ABC):
    id: str = ""
    category: str = ""
    description: str = ""
    language: str | None = None  # None = all languages

    @abstractmethod
    def get_patterns(self) -> list[RulePattern]:
        """Return the list of regex patterns for this rule."""

    def check(self, content: str, filepath: str) -> list[Finding]:
        """Scan content and return findings."""
        findings: list[Finding] = []
        suffix = Path(filepath).suffix
        tokens = _COMMENT_TOKENS.get(suffix, _DEFAULT_COMMENT_TOKENS)

        for rp in self.get_patterns():
            for match in rp._compiled.finditer(content):
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.start())
                if line_end == -1:
                    line_end = len(content)
                line_num = content.count("\n", 0, match.start()) + 1
                col = match.start() - line_start
                line_text = content[line_start:line_end]

                if _is_in_comment(line_text, col, tokens):
                    continue

                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        column=col,
                        category=self.category,
                        description=rp.description,
                        severity=rp.severity,
                        rule_id=rp.rule_id or self.id,
                        match=match.group()[:80],
                        confidence=rp.confidence,
                    )
                )

        return findings


def load_all_rules() -> list[Rule]:
    """Discover and instantiate all Rule subclasses."""
    from xecurex.rules.credentials import CredentialRules
    from xecurex.rules.crypto import CryptoRules
    from xecurex.rules.data_exposure import DataExposureRules
    from xecurex.rules.dependencies import DependencyRules
    from xecurex.rules.deserialization import DeserializationRules
    from xecurex.rules.hardcoded import HardcodedRules
    from xecurex.rules.injection import InjectionRules
    from xecurex.rules.path_traversal import PathTraversalRules
    from xecurex.rules.xss import XSSRules

    return [
        CredentialRules(),
        InjectionRules(),
        XSSRules(),
        CryptoRules(),
        DeserializationRules(),
        PathTraversalRules(),
        DataExposureRules(),
        HardcodedRules(),
        DependencyRules(),
    ]
