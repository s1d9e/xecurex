"""Tests for insecure deserialization detection rules."""

from xecurex.models import Severity
from xecurex.rules.deserialization import DeserializationRules


class TestDeserializationRules:
    def setup_method(self):
        self.rule = DeserializationRules()

    def test_detects_pickle_load(self):
        code = "pickle.load(file)"
        findings = self.rule.check(code, "test.py")
        assert any("pickle" in f.description.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_pickle_loads(self):
        code = "pickle.loads(data)"
        findings = self.rule.check(code, "test.py")
        assert any("pickle" in f.description.lower() for f in findings)

    def test_detects_yaml_load_without_loader(self):
        code = "yaml.load(data)"
        findings = self.rule.check(code, "test.py")
        assert any("yaml.load" in f.description for f in findings)

    def test_detects_yaml_unsafe_load(self):
        code = "yaml.unsafe_load(data)"
        findings = self.rule.check(code, "test.py")
        assert any("unsafe" in f.description.lower() for f in findings)

    def test_detects_marshal_loads(self):
        code = "marshal.loads(data)"
        findings = self.rule.check(code, "test.py")
        assert any("marshal" in f.description.lower() for f in findings)

    def test_detects_php_unserialize(self):
        code = "unserialize($data)"
        findings = self.rule.check(code, "test.php")
        assert any("unserialize" in f.description for f in findings)

    def test_ignores_commented_code(self):
        code = "# pickle.load(file)"
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0
