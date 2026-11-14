"""Tests for the generic analyzer and comment stripping."""

import pytest

from xecurex.analyzers.generic_analyzer import GenericAnalyzer, strip_comments
from xecurex.rules.base import load_all_rules


@pytest.fixture
def analyzer():
    return GenericAnalyzer(load_all_rules())


class TestStripComments:
    def test_preserves_line_count(self):
        code = '# comment\npassword = "secret123456"\n# another'
        stripped = strip_comments(code, "test.py")
        assert len(stripped.split("\n")) == len(code.split("\n"))

    def test_full_line_comment_blanked(self):
        code = '# password = "secret123456"'
        stripped = strip_comments(code, "test.py")
        assert "password" not in stripped

    def test_inline_comment_blanked(self):
        code = 'x = 1  # password = "secret123456"'
        stripped = strip_comments(code, "test.py")
        assert "password" not in stripped
        assert stripped.startswith("x = 1")

    def test_inline_comment_preserves_length(self):
        code = "x = 1  # trailing comment"
        stripped = strip_comments(code, "test.py")
        assert len(stripped) == len(code)

    def test_hash_inside_string_kept(self):
        code = 'color = "#ffffff"'
        stripped = strip_comments(code, "test.py")
        assert "#ffffff" in stripped

    def test_docstring_stripped_preserves_lines(self):
        code = 'def f():\n    """\n    password = "x"\n    """\n    return 1'
        stripped = strip_comments(code, "test.py")
        lines = stripped.split("\n")
        assert len(lines) == 5
        assert "password" not in stripped
        assert lines[4] == "    return 1"

    def test_single_line_docstring_blanked(self):
        code = 'def f():\n    """Doc with password = "x""""\n    return 1'
        stripped = strip_comments(code, "test.py")
        assert "password" not in stripped
        assert "return 1" in stripped

    def test_js_block_comment(self):
        code = '/*\npassword = "secret"\n*/\nvar x = 1'
        stripped = strip_comments(code, "test.js")
        lines = stripped.split("\n")
        assert len(lines) == 4
        assert "password" not in stripped
        assert lines[3] == "var x = 1"

    def test_js_line_comment(self):
        code = '// password = "secret"\nvar x = 1'
        stripped = strip_comments(code, "test.js")
        assert "password" not in stripped
        assert "var x = 1" in stripped

    def test_url_slashes_not_treated_as_comment(self):
        code = 'var url = "http://example.com/api";'
        stripped = strip_comments(code, "test.js")
        assert "http://example.com/api" in stripped

    def test_block_comment_inline(self):
        code = "var a = 1; /* secret */ var b = 2;"
        stripped = strip_comments(code, "test.js")
        assert "secret" not in stripped
        assert "var a = 1" in stripped
        assert "var b = 2" in stripped

    def test_sql_line_comment(self):
        code = '-- password = "secret"\nSELECT 1'
        stripped = strip_comments(code, "test.sql")
        assert "password" not in stripped
        assert "SELECT 1" in stripped

    def test_shell_comment(self):
        code = '# password="secret"\necho hi'
        stripped = strip_comments(code, "test.sh")
        assert "password" not in stripped
        assert "echo hi" in stripped

    def test_unknown_extension_untouched(self):
        code = "# comment\nvalue = 1"
        assert strip_comments(code, "test.xyz") == code


class TestGenericAnalyzer:
    def test_finds_xss_in_js(self, analyzer):
        code = 'document.getElementById("x").innerHTML = userInput'
        findings = analyzer.analyze(code, "app.js")
        assert any(f.category == "XSS" for f in findings)

    def test_ignores_commented_findings(self, analyzer):
        code = '// password = "secret123456"\nvar x = 1'
        findings = analyzer.analyze(code, "app.js")
        assert not any(f.category == "Hardcoded Credentials" for f in findings)

    def test_finding_line_numbers_after_strip(self, analyzer):
        code = '// comment\n// comment 2\npassword = "secret123456"'
        findings = analyzer.analyze(code, "app.js")
        cred = [f for f in findings if f.category == "Hardcoded Credentials"]
        assert cred
        assert all(f.line == 3 for f in cred)

    def test_docstring_content_ignored_for_python(self, analyzer):
        code = 'def f():\n    """\n    password = "secret123456"\n    """\n    return 1'
        findings = analyzer.analyze(code, "app.py")
        assert not any(f.category == "Hardcoded Credentials" for f in findings)
