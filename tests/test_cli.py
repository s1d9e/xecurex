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

    def test_config_file_min_severity_respected(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text('[xecurex]\nmin_severity = "high"\n')
        (temp_repo / "app.py").write_text("hashlib.md5(data)")
        # MEDIUM finding must be filtered by the config file value.
        exit_code = main([str(temp_repo)])
        assert exit_code == 0

    def test_cli_flag_overrides_config(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text('[xecurex]\nmin_severity = "high"\n')
        (temp_repo / "app.py").write_text("hashlib.md5(data)")
        exit_code = main([str(temp_repo), "--min-severity", "low"])
        assert exit_code == 1

    def test_config_confidence_threshold_respected(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text("[xecurex]\nconfidence_threshold = 1.0\n")
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo)])
        assert exit_code == 0

    def test_no_config_flag_ignores_config_file(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text('[xecurex]\nmin_severity = "high"\n')
        (temp_repo / "app.py").write_text("hashlib.md5(data)")
        exit_code = main([str(temp_repo), "--no-config"])
        assert exit_code == 1

    def test_no_ast_flag(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo), "--no-ast"])
        assert exit_code == 1

    def test_output_file_written_as_utf8(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        output_file = temp_repo / "report.json"
        main([str(temp_repo), "--format", "json", "-o", str(output_file)])
        content = output_file.read_text(encoding="utf-8")
        assert '"findings"' in content

    def test_sarif_output(self, temp_repo, capsys):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo), "--format", "sarif"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert '"version": "2.1.0"' in captured.out
        assert "sarif-2.1.0" in captured.out
        assert '"ruleId"' in captured.out

    def test_sarif_output_file(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        output_file = temp_repo / "report.sarif"
        main([str(temp_repo), "--format", "sarif", "-o", str(output_file)])
        content = output_file.read_text(encoding="utf-8")
        assert '"runs"' in content

    def test_baseline_json_suppresses_findings(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        baseline = temp_repo / "baseline.json"

        # First scan produces the baseline report.
        main([str(temp_repo), "--format", "json", "-o", str(baseline)])
        assert baseline.exists()

        # Second scan with the baseline suppresses everything.
        exit_code = main([str(temp_repo), "--baseline", str(baseline)])
        assert exit_code == 0

    def test_baseline_text_format(self, temp_repo, capsys):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        baseline = temp_repo / "baseline.txt"
        baseline.write_text("# known finding\napp.py:1:CRED-AST-001\n", encoding="utf-8")

        # The AST finding is the only one left after dedup: baseline → clean.
        exit_code = main([str(temp_repo), "--format", "json", "--baseline", str(baseline)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "CRED-AST-001" not in captured.out
        assert '"total": 0' in captured.out

    def test_baseline_missing_file_returns_2(self, temp_repo, capsys):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        exit_code = main([str(temp_repo), "--baseline", "/no/such/baseline.json"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "baseline" in captured.err

    def test_xecurexignore_excludes_paths(self, temp_repo):
        from xecurex.config import load_config
        from xecurex.scanner import Scanner

        (temp_repo / ".xecurexignore").write_text(
            "# our fixtures\nfixtures\n*.generated.js\n", encoding="utf-8"
        )
        fixtures = temp_repo / "fixtures"
        fixtures.mkdir()
        (fixtures / "data.py").write_text('password = "secret123456"')
        (temp_repo / "app.generated.js").write_text('password = "secret123456"')
        (temp_repo / "app.py").write_text('password = "secret123456"')

        result = Scanner(load_config(temp_repo)).scan(temp_repo)
        files = {f.file for f in result.findings}
        assert "app.py" in files
        assert not any("fixtures" in f for f in files)
        assert not any("generated" in f for f in files)
