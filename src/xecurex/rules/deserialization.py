"""Rules for detecting insecure deserialization."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class DeserializationRules(Rule):
    id = "DESERN"
    category = "Insecure Deserialization"
    description = "Unsafe deserialization patterns that can lead to code execution"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""pickle\.loads?\s*\(""",
                description="Pickle deserialization — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.95,
            ),
            RulePattern(
                pattern=r"""yaml\.load\s*\((?!.*Loader\s*=)""",
                description="Unsafe yaml.load() — use yaml.safe_load()",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""yaml\.unsafe_load\s*\(""",
                description="yaml.unsafe_load() — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.95,
            ),
            RulePattern(
                pattern=r"""marshal\.loads?\s*\(""",
                description="marshal deserialization — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""shelve\.open\s*\(""",
                description="shelve.open() uses pickle under the hood — deserialization risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""jsonpickle\.decode\s*\(""",
                description="jsonpickle deserialization — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""unserialize\s*\(""",
                description="PHP unserialize — insecure deserialization",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""serialize\s*\(.*unserialize""",
                description="PHP serialize/unserialize usage detected",
                severity=Severity.MEDIUM,
                confidence=0.6,
            ),
        ]
