"""Rules for detecting XSS vulnerabilities."""

from xecurex.models import Severity
from xecurex.rules.base import Rule, RulePattern


class XSSRules(Rule):
    id = "XSS"
    category = "XSS"
    description = "Cross-site scripting vulnerabilities"

    def get_patterns(self) -> list[RulePattern]:
        return [
            RulePattern(
                pattern=r"""\.innerHTML\s*=""",
                description="Dangerous innerHTML assignment — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""document\.write\s*\(""",
                description="document.write() usage — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.75,
            ),
            RulePattern(
                pattern=r"""dangerouslySetInnerHTML""",
                description="React dangerouslySetInnerHTML — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""\.outerHTML\s*=""",
                description="Dangerous outerHTML assignment — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""document\.writeln\s*\(""",
                description="document.writeln() usage — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.75,
            ),
            RulePattern(
                pattern=r"""\.insertAdjacentHTML\s*\(""",
                description="insertAdjacentHTML — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.8,
            ),
            RulePattern(
                pattern=r"""\.html\s*\(\s*[^)]*\+""",
                description="jQuery .html() with concatenation — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.7,
            ),
            RulePattern(
                pattern=r"""\.append\s*\(\s*[^)]*\+""",
                description="jQuery .append() with concatenation — XSS risk",
                severity=Severity.MEDIUM,
                confidence=0.65,
            ),
        ]
