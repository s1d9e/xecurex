"""Abstract base class for security rules."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from xecurex.models import Finding, Severity


@dataclass
class RulePattern:
    pattern: str
    description: str
    severity: Severity
    confidence: float = 1.0
    flags: int = re.IGNORECASE | re.MULTILINE
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
        lines = content.split("\n")

        for rp in self.get_patterns():
            for match in rp._compiled.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                if self._is_in_comment(line_text, match):
                    continue

                col = match.start() - content.rfind("\n", 0, match.start()) - 1
                match_text = match.group()[:80]

                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        column=max(0, col),
                        category=self.category,
                        description=rp.description,
                        severity=rp.severity,
                        rule_id=self.id,
                        match=match_text,
                        confidence=rp.confidence,
                    )
                )

        return findings

    def _is_in_comment(self, line_text: str, match: re.Match) -> bool:
        stripped = line_text.lstrip()
        col = (
            match.start() - line_text.rfind("\n", 0, match.start()) - 1
            if "\n" in line_text[: match.start()]
            else match.start()
        )

        prefix = line_text[:col].lstrip() if col < len(line_text) else stripped

        if stripped.startswith("#") or stripped.startswith("//"):
            return True
        if stripped.startswith("*") or stripped.startswith("/*"):
            return True
        return prefix.startswith("'''") or prefix.startswith('"""')


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
