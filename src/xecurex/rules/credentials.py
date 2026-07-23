"""Rules for detecting hardcoded credentials."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class CredentialRules(Rule):
    id = "CRED"
    category = "Hardcoded Credentials"
    description = "Hardcoded passwords, API keys, secrets, or tokens in source code"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""(?<!\w)password\s*=\s*(["'])(?:(?!\1).){8,}\1""",
                description="Hardcoded password detected",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:api[_-]?key|apikey)\s*=\s*(["'])(?:(?!\1).){10,}\1""",
                description="Hardcoded API key detected",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""(?<!\w)secret\s*=\s*(["'])(?:(?!\1).){10,}\1""",
                description="Hardcoded secret detected",
                severity=Severity.HIGH,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:auth[_-]?token|access[_-]?token)\s*=\s*(["'])(?:(?!\1).){20,}\1""",
                description="Hardcoded auth/access token detected",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""(?<!\w)aws[_-]?(?:access[_-]?(?:key|id)|secret[_-]?key)[\w_-]*\s*[=:]\s*["']""",
                description="AWS credentials in code",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:private[_-]?key|privatekey)\s*[=:]\s*["']-----BEGIN""",
                description="Hardcoded private key detected",
                severity=Severity.HIGH,
                confidence=0.95,
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:password|passwd|pwd)\s*[:=]\s*(["'])(?:(?!\1).){3,}\1""",
                description="Hardcoded password/credential detected",
                severity=Severity.HIGH,
                confidence=0.75,
            ),
            RulePattern(
                pattern=r"""(?<!\w)token\s*=\s*(["'])[a-zA-Z0-9_\-.]{20,}\1""",
                description="Hardcoded token detected",
                severity=Severity.HIGH,
                confidence=0.7,
            ),
        ]
