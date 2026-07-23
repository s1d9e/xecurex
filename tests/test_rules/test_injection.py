"""Tests for injection detection rules."""

from xecurex.models import Severity
from xecurex.rules.injection import InjectionRules


class TestInjectionRules:
    def setup_method(self):
        self.rule = InjectionRules()

    def test_detects_os_system(self):
        code = 'os.system("ls")'
        findings = self.rule.check(code, "test.py")
        assert any("os.system" in f.description for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_subprocess_shell_true(self):
        code = 'subprocess.run("ls", shell=True)'
        findings = self.rule.check(code, "test.py")
        assert any("shell=True" in f.description for f in findings)

    def test_detects_eval(self):
        code = "eval(user_input)"
        findings = self.rule.check(code, "test.py")
        assert any("eval()" in f.description for f in findings)

    def test_detects_exec(self):
        code = "exec(malicious_code)"
        findings = self.rule.check(code, "test.py")
        assert any("exec()" in f.description for f in findings)

    def test_detects_sql_concatenation(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)'
        findings = self.rule.check(code, "test.py")
        assert any("SQL" in f.description for f in findings)

    def test_detects_fstring_sql(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
        findings = self.rule.check(code, "test.py")
        assert any("f-string SQL" in f.description for f in findings)

    def test_detects_os_popen(self):
        code = 'os.popen("ls")'
        findings = self.rule.check(code, "test.py")
        assert any("os.popen" in f.description for f in findings)

    def test_detects_new_function(self):
        code = 'new Function("return 1")'
        findings = self.rule.check(code, "test.js")
        assert any("new Function()" in f.description for f in findings)

    def test_ignores_subprocess_without_shell(self):
        code = 'subprocess.run(["ls", "-la"])'
        findings = self.rule.check(code, "test.py")
        assert not any("shell=True" in f.description for f in findings)

    def test_ignores_commented_code(self):
        code = '# os.system("ls")'
        findings = self.rule.check(code, "test.py")
        assert len(findings) == 0
