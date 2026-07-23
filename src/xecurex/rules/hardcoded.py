"""Rules for detecting hardcoded IPs and URLs."""

import re

from xecurex.models import Finding, Severity
from xecurex.rules.base import Rule, RulePattern

_PRIVATE_IP = re.compile(
    r"^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|0\.0\.0\.0"
    r"|255\.255\.255\.255)$"
)

_VERSION_LIKE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


class HardcodedRules(Rule):
    id = "HARDCODE"
    category = "Hardcoded IP/URL"
    description = "Hardcoded IP addresses and insecure URLs in source code"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""",
                description="Hardcoded IP address detected",
                severity=Severity.LOW,
                confidence=0.5,
            ),
            RulePattern(
                pattern=r"""http://[^"'\s]{10,}""",
                description="Insecure HTTP URL (should use HTTPS)",
                severity=Severity.LOW,
                confidence=0.6,
            ),
        ]

    def check(self, content: str, filepath: str) -> list[Finding]:
        findings = super().check(content, filepath)

        filtered = []
        for f in findings:
            if f.description == "Hardcoded IP address detected":
                ip = f.match.strip()
                if _PRIVATE_IP.match(ip) or _VERSION_LIKE.match(ip):
                    continue
            filtered.append(f)

        return filtered
