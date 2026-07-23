"""Tests for the CLI."""

import pytest

from xecurex.cli import main


class TestCLI:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0

    def test_scan_text_output(self, temp_repo, capsys):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "SECURITY AUDIT REPORT" in captured.out

    def test_scan_json_output(self, temp_repo, capsys):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo), "--format", "json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert '"findings"' in captured.out

    def test_clean_exit_on_no_findings(self, temp_repo):
        (temp_repo / "app.py").write_text("x = 1\ny = 2\n")
        exit_code = main([str(temp_repo)])
        assert exit_code == 0

    def test_nonexistent_path(self, capsys):
        exit_code = main(["/nonexistent/path"])
        assert exit_code == 2

    def test_min_severity_flag(self, temp_repo):
        (temp_repo / "app.py").write_text("hashlib.md5(data)")
        exit_code = main([str(temp_repo), "--min-severity", "high"])
        assert exit_code == 0

    def test_exclude_flag(self, temp_repo):
        nm = temp_repo / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('password = "secret123456"')
        (temp_repo / "app.js").write_text("var x = 1")
        exit_code = main([str(temp_repo), "--exclude", "custom_dir"])
        assert exit_code == 0

    def test_output_flag(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        output_file = temp_repo / "report.json"
        main([str(temp_repo), "--format", "json", "-o", str(output_file)])
        assert output_file.exists()
