"""Tests for the Python AST analyzer."""

import pytest

from xecurex.analyzers.python_analyzer import PythonAnalyzer
from xecurex.rules.base import load_all_rules


@pytest.fixture
def analyzer():
    rules = load_all_rules()
    return PythonAnalyzer(rules)


class TestPythonAnalyzer:
    def test_detects_os_system(self, analyzer):
        code = 'import os\nos.system("ls")'
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("os.system" in f.description for f in ast_findings)

    def test_detects_eval(self, analyzer):
        code = "eval(user_input)"
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("eval()" in f.description for f in ast_findings)

    def test_detects_exec(self, analyzer):
        code = "exec(malicious_code)"
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("exec()" in f.description for f in ast_findings)

    def test_detects_pickle_load(self, analyzer):
        code = "import pickle\ndata = pickle.load(file)"
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("pickle" in f.description.lower() for f in ast_findings)

    def test_detects_hashlib_md5(self, analyzer):
        code = "import hashlib\nh = hashlib.md5(data)"
        findings = analyzer.analyze(code, "test.py")
        assert any("MD5" in f.description for f in findings)

    def test_detects_subprocess_shell_true(self, analyzer):
        code = 'import subprocess\nsubprocess.run("ls", shell=True)'
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("shell=True" in f.description for f in ast_findings)

    def test_detects_hardcoded_password_assignment(self, analyzer):
        code = 'password = "supersecretpassword123"'
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id]
        assert any("hardcoded" in f.description.lower() for f in ast_findings)

    def test_ignores_env_reference(self, analyzer):
        code = 'password = os.environ["DB_PASSWORD"]'
        findings = analyzer.analyze(code, "test.py")
        ast_findings = [f for f in findings if "AST" in f.rule_id and "Hardcoded" in f.category]
        assert len(ast_findings) == 0

    def test_falls_back_to_regex(self, analyzer):
        code = 'password = "supersecretpassword123"'
        findings = analyzer.analyze(code, "test.py")
        assert len(findings) > 0

    def test_handles_syntax_error_gracefully(self, analyzer):
        code = "def broken(\n    this is not valid python"
        findings = analyzer.analyze(code, "test.py")
        assert isinstance(findings, list)

    def test_handles_null_bytes(self, analyzer):
        code = 'password = "secret123456"\x00'
        findings = analyzer.analyze(code, "test.py")
        assert isinstance(findings, list)

    def test_no_duplicate_ast_and_regex_findings(self, analyzer):
        code = 'import os\nos.system("ls")'
        findings = analyzer.analyze(code, "test.py")
        line2 = [f for f in findings if f.line == 2]
        assert len(line2) == 1
        assert "AST" in line2[0].rule_id

    def test_ignores_placeholder_assignment(self, analyzer):
        code = 'password = "your_password"'
        findings = analyzer.analyze(code, "test.py")
        assert not any(f.category == "Hardcoded Credentials" for f in findings)

    def test_ignores_credential_text_inside_string(self, analyzer):
        code = "msg = 'password = \"abcdef123456\"'"
        findings = analyzer.analyze(code, "test.py")
        assert not any(f.category == "Hardcoded Credentials" for f in findings)

    def test_ignores_docstring_content(self, analyzer):
        code = 'def f():\n    """\n    password = "secret123456"\n    """\n    return 1'
        findings = analyzer.analyze(code, "test.py")
        assert not any(f.category == "Hardcoded Credentials" for f in findings)

    def test_line_numbers_survive_comment_stripping(self, analyzer):
        code = '# comment\n# comment\npassword = "supersecret123"'
        findings = analyzer.analyze(code, "test.py")
        cred = [f for f in findings if f.category == "Hardcoded Credentials"]
        assert cred
        assert all(f.line == 3 for f in cred)

    def test_eval_and_exec_both_reported(self, analyzer):
        code = "eval(x); exec(y)"
        findings = analyzer.analyze(code, "test.py")
        descriptions = " ".join(f.description for f in findings)
        assert "eval()" in descriptions
        assert "exec()" in descriptions
