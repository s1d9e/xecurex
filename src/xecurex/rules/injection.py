"""Rules for detecting injection vulnerabilities."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class InjectionRules(Rule):
    id = "INJECT"
    category = "Injection"
    description = "SQL injection, command injection, and code execution vulnerabilities"

    def get_patterns(self) -> list[RulePattern]:
        return [
            # SQL Injection
            RulePattern(
                pattern=r"""\.execute\s*\([^)]*\+[^)]*\)""",
                description="SQL query with string concatenation — SQL injection risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""\.execute\s*\([^)]*%\s*s[^)]*\+""",
                description="SQL query with %-formatting and concatenation — SQL injection risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""f["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE).*\{""",
                description="f-string SQL query — SQL injection risk",
                severity=Severity.HIGH,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""\.execute\s*\(["\'].*\+\s*\w+""",
                description="SQL query concatenating variable — SQL injection risk",
                severity=Severity.HIGH,
                confidence=0.8,
            ),
            # Command Injection
            RulePattern(
                pattern=r"""(?<!\w)os\.system\s*\(""",
                description="os.system() call — command injection risk",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True""",
                description="subprocess with shell=True — command injection risk",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            RulePattern(
                pattern=r"""(?<!\w|\.)(?<!test_)eval\s*\((?!.*#.*safe)""",
                description="eval() usage — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""(?<!\w)exec\s*\(""",
                description="exec() usage — arbitrary code execution risk",
                severity=Severity.HIGH,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""os\.popen\s*\(""",
                description="os.popen() call — command injection risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""commands\.getoutput\s*\(""",
                description="commands.getoutput() — command injection risk",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            # Code Injection (JS)
            RulePattern(
                pattern=r"""new\s+Function\s*\(""",
                description="new Function() — code injection risk",
                severity=Severity.HIGH,
                confidence=0.85,
            ),
            RulePattern(
                pattern=r"""setTimeout\s*\(\s*["\']""",
                description="setTimeout with string — code injection risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""setInterval\s*\(\s*["\']""",
                description="setInterval with string — code injection risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
        ]
