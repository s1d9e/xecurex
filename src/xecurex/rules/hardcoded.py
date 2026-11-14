"""Rules for detecting hardcoded IPs and URLs."""

import re

from xecurex.models import Finding, Severity
from xecurex.rules.base import Rule, RulePattern, is_placeholder

_PRIVATE_IP = re.compile(
    r"^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|0\.0\.0\.0"
    r"|255\.255\.255\.255)$"
)

# A quad of numbers is treated as a version, not an IP, when the line
# clearly talks about versions/releases.
_VERSION_CONTEXT = re.compile(
    r"\b(?:version|revision|release|build|ver)\b|(?<![\w.])v\d+\.\d+",
    re.IGNORECASE,
)

_EXAMPLE_HOSTS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "test.com",
        "domain.com",
    }
)

_URL_HOST = re.compile(r"^https?://([^/:?#]+)", re.IGNORECASE)


class HardcodedRules(Rule):
    id = "HARDCODE"
    category = "Hardcoded IP/URL"
    description = "Hardcoded IP addresses and insecure URLs in source code"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""(?<![\w./])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""",
                description="Hardcoded IP address detected",
                severity=Severity.LOW,
                confidence=0.5,
                rule_id="HARDCODE-001",
            ),
            RulePattern(
                pattern=r"""http://[^"'\s]{10,}""",
                description="Insecure HTTP URL (should use HTTPS)",
                severity=Severity.LOW,
                confidence=0.6,
                rule_id="HARDCODE-002",
            ),
        ]

    def check(self, content: str, filepath: str) -> list[Finding]:
        findings = super().check(content, filepath)
        lines = content.split("\n")

        filtered = []
        for f in findings:
            if f.description == "Hardcoded IP address detected":
                ip = f.match.strip()
                if _PRIVATE_IP.match(ip):
                    continue
                line_text = lines[f.line - 1] if 0 < f.line <= len(lines) else ""
                if _VERSION_CONTEXT.search(line_text):
                    continue
            elif f.description.startswith("Insecure HTTP URL"):
                m = _URL_HOST.match(f.match)
                if m and m.group(1).lower() in _EXAMPLE_HOSTS:
                    continue
                if is_placeholder(f.match):
                    continue
            filtered.append(f)

        return filtered
