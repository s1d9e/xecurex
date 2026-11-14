"""Tests for sensitive data exposure rules."""

from xecurex.models import Severity
from xecurex.rules.data_exposure import DataExposureRules


class TestDataExposureRules:
    def setup_method(self):
        self.rule = DataExposureRules()

    def test_detects_console_log_password(self):
        code = 'console.log("password:", password)'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "EXPOSE-001" for f in findings)

    def test_detects_print_secret(self):
        code = 'print("secret:", secret)'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "EXPOSE-002" for f in findings)

    def test_detects_logging_token(self):
        code = 'logging.info("token = %s", token)'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "EXPOSE-003" for f in findings)

    def test_detects_console_warn_credential(self):
        code = 'console.warn("credential", cred)'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "EXPOSE-004" for f in findings)

    def test_detects_console_error_key(self):
        code = 'console.error("api key:", key)'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "EXPOSE-005" for f in findings)

    def test_detects_stdout_write_password(self):
        code = 'sys.stdout.write("password: " + pwd)'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "EXPOSE-006" for f in findings)

    def test_ignores_benign_console_log(self):
        code = 'console.log("server started")'
        findings = self.rule.check(code, "test.js")
        assert len(findings) == 0

    def test_ignores_commented_log(self):
        code = '// console.log("password:", password)'
        findings = self.rule.check(code, "test.js")
        assert len(findings) == 0

    def test_findings_are_low_severity(self):
        code = 'print("secret:", secret)'
        findings = self.rule.check(code, "test.py")
        expose = [f for f in findings if f.rule_id == "EXPOSE-002"]
        assert expose
        assert all(f.severity == Severity.LOW for f in expose)
