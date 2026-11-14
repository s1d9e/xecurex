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

    def test_ignores_commented_code_with_leading_code(self):
        code = 'x = 1  # password = "supersecret123"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_placeholder_your_password(self):
        code = 'password = "your_password"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_placeholder_env_syntax(self):
        code = 'password = "${DB_PASSWORD}"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_placeholder_generic(self):
        code = 'password = "placeholder"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_ignores_placeholder_angle_brackets(self):
        code = 'api_key = "<YOUR_API_KEY_HERE>"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description == "Hardcoded API key detected" for f in findings)

    def test_ignores_placeholder_changeme(self):
        code = 'password = "changeme"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0

    def test_detects_real_looking_password(self):
        code = 'password = "S3cr3t!vAlue99"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) >= 1

    def test_rule_ids_are_unique(self):
        code = 'password = "supersecret123"'
        findings = self.rule.check(code, "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert len(rule_ids) == len(set(rule_ids))
