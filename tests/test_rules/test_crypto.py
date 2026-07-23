"""Tests for weak cryptography detection rules."""

from xecurex.models import Severity
from xecurex.rules.crypto import CryptoRules


class TestCryptoRules:
    def setup_method(self):
        self.rule = CryptoRules()

    def test_detects_md5(self):
        code = "hashlib.md5(data)"
        findings = self.rule.check(code, "test.py")
        assert any("MD5" in f.description for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_detects_sha1(self):
        code = "hashlib.sha1(data)"
        findings = self.rule.check(code, "test.py")
        assert any("SHA-1" in f.description for f in findings)

    def test_detects_hashlib_new_md5(self):
        code = 'hashlib.new("md5", data)'
        findings = self.rule.check(code, "test.py")
        assert any("weak" in f.description.lower() for f in findings)

    def test_detects_weak_cipher(self):
        code = "Crypto.Cipher.DES.new(key)"
        findings = self.rule.check(code, "test.py")
        assert any("cipher" in f.description.lower() for f in findings)

    def test_detects_math_random(self):
        code = "Math.random()"
        findings = self.rule.check(code, "test.js")
        assert any("Math.random" in f.description for f in findings)

    def test_ignores_commented_code(self):
        code = "# hashlib.md5(data)"
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0
