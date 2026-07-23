"""Rules for detecting path traversal vulnerabilities."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class PathTraversalRules(Rule):
    id = "PATH"
    category = "Path Traversal"
    description = "File path manipulation that could allow directory traversal"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""open\s*\([^,)]*\+[^,)]*\)""",
                description="Dynamic file path in open() — path traversal risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""\.\.\/""",
                description="Path traversal pattern (../) detected",
                severity=Severity.MEDIUM,
                confidence=0.5,
            ),
            RulePattern(
                pattern=r"""\.\.\\""",
                description="Path traversal pattern (..\\) detected",
                severity=Severity.MEDIUM,
                confidence=0.5,
            ),
            RulePattern(
                pattern=r"""readfile\s*\(""",
                description="readfile() with potential path traversal",
                severity=Severity.MEDIUM,
                confidence=0.6,
            ),
            RulePattern(
                pattern=r"""readFileSync\s*\([^)]*\+""",
                description="Node.js readFileSync with dynamic path — path traversal risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""fs\.readFile\s*\([^)]*\+""",
                description="Node.js fs.readFile with dynamic path — path traversal risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""path\.join\s*\(\s*["']\.\.""",
                description="path.join starting with '..' — path traversal risk",
                severity=Severity.MEDIUM,
                confidence=0.75,
            ),
        ]
