"""Tests for XSS detection rules."""

from xecurex.models import Severity
from xecurex.rules.xss import XSSRules


class TestXSSRules:
    def setup_method(self):
        self.rule = XSSRules()

    def test_detects_innerhtml(self):
        code = 'document.getElementById("app").innerHTML = userInput'
        findings = self.rule.check(code, "test.js")
        assert any("innerHTML" in f.description for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_detects_document_write(self):
        code = "document.write(userInput)"
        findings = self.rule.check(code, "test.js")
        assert any("document.write" in f.description for f in findings)

    def test_detects_dangerously_set_inner_html(self):
        code = "<div dangerouslySetInnerHTML={{__html: userInput}} />"
        findings = self.rule.check(code, "test.jsx")
        assert any("dangerouslySetInnerHTML" in f.description for f in findings)

    def test_detects_outerhtml(self):
        code = 'element.outerHTML = "<img src=x onerror=alert(1)>";'
        findings = self.rule.check(code, "test.js")
        assert any("outerHTML" in f.description for f in findings)

    def test_ignores_commented_code(self):
        code = "// document.write(userInput)"
        findings = self.rule.check(code, "test.js")
        assert len(findings) == 0

    def test_detects_jquery_html_concat(self):
        code = '$("#app").html("<b>" + userInput)'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "XSS-007" for f in findings)

    def test_detects_jquery_append_concat(self):
        code = '$(".items").append("<li>" + userInput)'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "XSS-008" for f in findings)

    def test_ignores_python_list_append(self):
        code = 'out.append(" " * consumed + rest)'
        findings = self.rule.check(code, "test.py")
        assert not any(f.rule_id == "XSS-008" for f in findings)

    def test_ignores_python_html_method(self):
        code = "doc.html(content + suffix)"
        findings = self.rule.check(code, "test.py")
        assert not any(f.rule_id == "XSS-007" for f in findings)
