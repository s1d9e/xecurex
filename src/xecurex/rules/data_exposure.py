"""Rules for detecting sensitive data exposure."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class DataExposureRules(Rule):
    id = "EXPOSE"
    category = "Sensitive Data Exposure"
    description = "Sensitive data logged or printed to console"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""console\.log\s*\([^)]*(?:password|secret|token|key|credential)""",
                description="Sensitive data in console.log()",
                severity=Severity.LOW,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""print\s*\(.*(?:password|secret|token|key|credential)""",
                description="Sensitive data in print()",
                severity=Severity.LOW,
                confidence=0.65,
            ),
            RulePattern(
                pattern=r"""logging\.\w+\s*\(.*(?:password|secret|token|key|credential)""",
                description="Sensitive data in logging call",
                severity=Severity.LOW,
                confidence=0.6,
            ),
            RulePattern(
                pattern=r"""console\.warn\s*\([^)]*(?:password|secret|token|key|credential)""",
                description="Sensitive data in console.warn()",
                severity=Severity.LOW,
                confidence=0.65,
            ),
            RulePattern(
                pattern=r"""console\.error\s*\([^)]*(?:password|secret|token|key|credential)""",
                description="Sensitive data in console.error()",
                severity=Severity.LOW,
                confidence=0.6,
            ),
            RulePattern(
                pattern=r"""sys\.stdout\.write\s*\(.*(?:password|secret|token|key)""",
                description="Sensitive data written to stdout",
                severity=Severity.LOW,
                confidence=0.65,
            ),
        ]
