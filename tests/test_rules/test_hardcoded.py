"""Tests for hardcoded IP/URL rules."""

from xecurex.rules.hardcoded import HardcodedRules


class TestHardcodedRules:
    def setup_method(self):
        self.rule = HardcodedRules()

    def test_detects_public_ip(self):
        code = 'server = "8.8.8.8"'
        findings = self.rule.check(code, "test.py")
        assert any(f.description == "Hardcoded IP address detected" for f in findings)

    def test_detects_http_url(self):
        code = 'url = "http://internal-service.local/api"'
        findings = self.rule.check(code, "test.py")
        assert any(f.description.startswith("Insecure HTTP URL") for f in findings)

    def test_ignores_private_ip(self):
        code = 'server = "192.168.1.1"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description == "Hardcoded IP address detected" for f in findings)

    def test_ignores_localhost_ip(self):
        code = 'server = "127.0.0.1"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description == "Hardcoded IP address detected" for f in findings)

    def test_ignores_version_like_quad(self):
        code = 'version = "1.2.3.4"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description == "Hardcoded IP address detected" for f in findings)

    def test_ignores_localhost_url(self):
        code = 'url = "http://localhost:8080/api"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description.startswith("Insecure HTTP URL") for f in findings)

    def test_ignores_example_com_url(self):
        code = 'url = "http://example.com/page"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.description.startswith("Insecure HTTP URL") for f in findings)

    def test_ip_inside_url_not_reported_twice(self):
        code = 'ping = "http://8.8.8.8/health"'
        findings = self.rule.check(code, "test.py")
        assert any(f.description.startswith("Insecure HTTP URL") for f in findings)
        assert not any(f.description == "Hardcoded IP address detected" for f in findings)

    def test_commented_ip_not_flagged(self):
        code = '# server = "8.8.8.8"'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0
