"""Rules for detecting weak cryptography usage."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class CryptoRules(Rule):
    id = "CRYPTO"
    category = "Weak Cryptography"
    description = "Usage of weak or deprecated cryptographic algorithms"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""hashlib\.md5\s*\(""",
                description="MD5 hash usage — weak, use SHA-256+",
                severity=Severity.MEDIUM,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""hashlib\.sha1\s*\(""",
                description="SHA-1 hash usage — weak, use SHA-256+",
                severity=Severity.MEDIUM,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""hashlib\.new\s*\(\s*["'](?:md5|sha1)["']""",
                description="Weak hash algorithm via hashlib.new()",
                severity=Severity.MEDIUM,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""Crypto\.Cipher\.(?:DES|Blowfish|RC4|ARC4)""",
                description="Weak symmetric cipher usage",
                severity=Severity.MEDIUM,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""(?:md5|sha1)\s*\(""",
                description="Weak hash function usage",
                severity=Severity.MEDIUM,
                confidence=0.6,
            ),
            RulePattern(
                pattern=r"""\.md5\s*\(""",
                description="MD5 digest usage — weak cryptographic hash",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""\.sha1\s*\(""",
                description="SHA-1 digest usage — weak cryptographic hash",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""Math\.random\s*\(""",
                description="Math.random() is not cryptographically secure",
                severity=Severity.LOW,
                confidence=0.6,
            ),
        ]
