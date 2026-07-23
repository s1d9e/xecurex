"""Tests for credential detection rules."""

from xecurex.models import Severity
from xecurex.rules.credentials import CredentialRules


class TestCredentialRules:
    def setup_method(self):
        self.rule = CredentialRules()

    def test_detects_hardcoded_password(self):
        code = 'password = "supersecret123"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == "Hardcoded Credentials"

    def test_detects_api_key(self):
        code = 'api_key = "ak_live_1234567890abcdef"'
        findings = self.rule.check(code, "test.py")
        assert any(f.description == "Hardcoded API key detected" for f in findings)

    def test_detects_secret(self):
        code = 'secret = "my_super_secret_value"'
        findings = self.rule.check(code, "test.py")
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_token(self):
        code = 'auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"'
        findings = self.rule.check(code, "test.py")
        assert any("token" in f.description.lower() for f in findings)

    def test_detects_aws_credentials(self):
        code = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        findings = self.rule.check(code, "test.py")
        assert any("AWS" in f.description for f in findings)

    def test_detects_private_key(self):
        code = 'private_key = "-----BEGIN RSA PRIVATE KEY-----"'
        findings = self.rule.check(code, "test.py")
        assert any("private key" in f.description.lower() for f in findings)

    def test_ignores_short_passwords(self):
        code = 'password = "ab"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_commented_code(self):
        code = '# password = "supersecret123"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_env_reference(self):
        code = 'password = os.environ["DB_PASSWORD"]'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_variable_reference(self):
        code = "password = get_password_from_vault()"
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0
