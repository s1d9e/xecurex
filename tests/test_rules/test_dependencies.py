"""Tests for insecure dependency rules."""

from xecurex.models import Severity
from xecurex.rules.dependencies import DependencyRules


class TestDependencyRules:
    def setup_method(self):
        self.rule = DependencyRules()

    def test_detects_crypto_require(self):
        code = 'const crypto = require("crypto")'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "DEP-001" for f in findings)

    def test_detects_jwt_import(self):
        code = "import jwt"
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "DEP-002" for f in findings)

    def test_detects_jwt_from_import(self):
        code = "from jwt import encode"
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "DEP-003" for f in findings)

    def test_jwt_from_import_not_double_reported(self):
        code = "from jwt import encode"
        findings = self.rule.check(code, "test.py")
        dep_ids = [f.rule_id for f in findings if f.rule_id.startswith("DEP-")]
        assert dep_ids == ["DEP-003"]

    def test_detects_eval_package(self):
        code = 'const ev = require("eval")'
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "DEP-004" for f in findings)

    def test_detects_telnetlib_import(self):
        code = "import telnetlib"
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "DEP-005" for f in findings)

    def test_detects_telnetlib_from_import(self):
        code = "from telnetlib import Telnet"
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "DEP-006" for f in findings)

    def test_telnetlib_from_import_not_double_reported(self):
        code = "from telnetlib import Telnet"
        findings = self.rule.check(code, "test.py")
        dep_ids = [f.rule_id for f in findings if f.rule_id.startswith("DEP-")]
        assert dep_ids == ["DEP-006"]

    def test_ignores_commented_import(self):
        code = "# import telnetlib"
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_no_jwt_false_positive(self):
        code = 'docs = "how to use the jsonwebtoken library"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.rule_id in ("DEP-002", "DEP-003") for f in findings)

    def test_telnetlib_severity(self):
        code = "import telnetlib"
        findings = self.rule.check(code, "test.py")
        telnet = [f for f in findings if f.rule_id == "DEP-005"]
        assert telnet
        assert all(f.severity == Severity.MEDIUM for f in telnet)
