"""Rules for detecting hardcoded credentials."""

import re

from xecurex.models import Finding, Severity
from xecurex.rules.base import Rule, RulePattern, is_placeholder


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
                rule_id="CRED-001",
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:api[_-]?key|apikey)\s*=\s*(["'])(?:(?!\1).){10,}\1""",
                description="Hardcoded API key detected",
                severity=Severity.HIGH,
                confidence=0.85,
                rule_id="CRED-002",
            ),
            RulePattern(
                pattern=r"""(?<!\w)secret\s*=\s*(["'])(?:(?!\1).){10,}\1""",
                description="Hardcoded secret detected",
                severity=Severity.HIGH,
                confidence=0.8,
                rule_id="CRED-003",
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:auth[_-]?token|access[_-]?token)\s*=\s*(["'])(?:(?!\1).){20,}\1""",
                description="Hardcoded auth/access token detected",
                severity=Severity.HIGH,
                confidence=0.85,
                rule_id="CRED-004",
            ),
            RulePattern(
                pattern=r"""(?<!\w)aws[_-]?(?:access[_-]?(?:key|id)|secret[_-]?key)[\w_-]*\s*[=:]\s*["']""",
                description="AWS credentials in code",
                severity=Severity.HIGH,
                confidence=0.9,
                rule_id="CRED-005",
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:private[_-]?key|privatekey)\s*[=:]\s*["']-----BEGIN""",
                description="Hardcoded private key detected",
                severity=Severity.HIGH,
                confidence=0.95,
                rule_id="CRED-006",
            ),
            RulePattern(
                pattern=r"""(?<!\w)(?:password|passwd|pwd)\s*[:=]\s*(["'])(?:(?!\1).){3,}\1""",
                description="Hardcoded password/credential detected",
                severity=Severity.HIGH,
                confidence=0.75,
                rule_id="CRED-007",
            ),
            RulePattern(
                pattern=r"""(?<!\w)token\s*=\s*(["'])[a-zA-Z0-9_\-.]{20,}\1""",
                description="Hardcoded token detected",
                severity=Severity.HIGH,
                confidence=0.7,
                rule_id="CRED-008",
            ),
        ]

    def check(self, content: str, filepath: str) -> list[Finding]:
        """Filter out findings whose value looks like a placeholder."""
        findings = super().check(content, filepath)
        return [f for f in findings if not self._is_placeholder(f.match)]

    @staticmethod
    def _is_placeholder(match_text: str) -> bool:
        m = re.search(r"""["']([^"']+)["']""", match_text)
        if m:
            return is_placeholder(m.group(1))
        # Patterns without a closing quote (e.g. AWS keys): check bare value.
        m = re.search(r"""[=:]\s*["']([^"']+)""", match_text)
        return bool(m) and is_placeholder(m.group(1))
