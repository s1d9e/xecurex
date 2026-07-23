"""Rules for detecting insecure dependencies and library usage."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class DependencyRules(Rule):
    id = "DEP"
    category = "Insecure Dependencies"
    description = "Usage of libraries with known security concerns"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""require\s*\(\s*["']crypto["']\s*\)""",
                description="Node.js crypto module — verify usage is secure",
                severity=Severity.LOW,
                confidence=0.4,
            ),
            RulePattern(
                pattern=r"""import\s+jwt\b""",
                description="JWT library usage — verify secure configuration",
                severity=Severity.LOW,
                confidence=0.5,
            ),
            RulePattern(
                pattern=r"""from\s+jwt\s+import""",
                description="JWT library import — verify secure configuration",
                severity=Severity.LOW,
                confidence=0.5,
            ),
            RulePattern(
                pattern=r"""require\s*\(\s*["']eval["']\s*\)""",
                description="eval npm package — code injection risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""import\s+telnetlib\b""",
                description="telnetlib usage — unencrypted protocol",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""from\s+telnetlib\s+import""",
                description="telnetlib import — unencrypted protocol",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
        ]
