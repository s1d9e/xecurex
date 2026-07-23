"""Data models for XecureX."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class Finding:
    file: str
    line: int
    column: int
    category: str
    description: str
    severity: Severity
    rule_id: str
    match: str
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "category": self.category,
            "description": self.description,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "match": self.match,
            "confidence": self.confidence,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    lines_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "files_skipped": self.files_skipped,
            "errors": self.errors,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    duration: float = 0.0

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.findings),
            "high": len(self.high),
            "medium": len(self.medium),
            "low": len(self.low),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "duration_seconds": round(self.duration, 2),
        }
