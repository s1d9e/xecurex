"""Tests for path traversal detection rules."""

from xecurex.models import Severity
from xecurex.rules.path_traversal import PathTraversalRules


class TestPathTraversalRules:
    def setup_method(self):
        self.rule = PathTraversalRules()

    def test_detects_dynamic_open(self):
        code = 'data = open(user_input + ".txt").read()'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "PATH-001" for f in findings)

    def test_detects_dotdot_slash(self):
        code = 'path = "../../etc/passwd"'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "PATH-002" for f in findings)

    def test_detects_dotdot_backslash(self):
        code = 'path = "..\\users\\admin"'
        findings = self.rule.check(code, "test.py")
        assert any(f.rule_id == "PATH-003" for f in findings)

    def test_detects_php_readfile(self):
        code = "readfile($_GET['file']);"
        findings = self.rule.check(code, "test.php")
        assert any(f.rule_id == "PATH-004" for f in findings)

    def test_detects_node_read_file_sync(self):
        code = "fs.readFileSync(base + userInput)"
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "PATH-005" for f in findings)

    def test_detects_node_fs_readfile(self):
        code = "fs.readFile(base + userInput, callback)"
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "PATH-006" for f in findings)

    def test_detects_path_join_dotdot(self):
        code = "p = path.join('../data', name)"
        findings = self.rule.check(code, "test.js")
        assert any(f.rule_id == "PATH-007" for f in findings)

    def test_static_path_not_flagged(self):
        code = 'data = open("config.json").read()'
        findings = self.rule.check(code, "test.py")
        assert not any(f.rule_id == "PATH-001" for f in findings)

    def test_findings_are_medium_severity(self):
        code = 'path = "../../etc/passwd"'
        findings = self.rule.check(code, "test.py")
        traversal = [f for f in findings if f.rule_id == "PATH-002"]
        assert traversal
        assert all(f.severity == Severity.MEDIUM for f in traversal)

    def test_commented_traversal_not_flagged(self):
        code = '# path = "../../etc/passwd"'
        findings = self.rule.check(code, "test.py")
        assert not any(f.rule_id == "PATH-002" for f in findings)
