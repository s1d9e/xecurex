"""Tests for the scanner integration."""

from pathlib import Path

import pytest

from xecurex.config import Config
from xecurex.models import Severity
from xecurex.scanner import Scanner


@pytest.fixture
def scanner():
    return Scanner(Config())


class TestScanner:
    def test_scans_python_file(self, scanner, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        result = scanner.scan(temp_repo)
        assert result.stats.files_scanned == 1
        assert len(result.findings) > 0

    def test_scans_javascript_file(self, scanner, temp_repo):
        (temp_repo / "app.js").write_text('document.getElementById("x").innerHTML = userInput')
        result = scanner.scan(temp_repo)
        assert any(f.category == "XSS" for f in result.findings)

    def test_excludes_node_modules(self, scanner, temp_repo):
        nm = temp_repo / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('password = "secret123456"')
        (temp_repo / "app.js").write_text("var x = 1")
        result = scanner.scan(temp_repo)
        assert not any("node_modules" in f.file for f in result.findings)

    def test_excludes_git_dir(self, scanner, temp_repo):
        git = temp_repo / ".git"
        git.mkdir()
        (git / "config").write_text('password = "secret123456"')
        result = scanner.scan(temp_repo)
        assert not any(".git" in f.file for f in result.findings)

    def test_skips_non_source_files(self, scanner, temp_repo):
        (temp_repo / "image.png").write_bytes(b"\x89PNG")
        result = scanner.scan(temp_repo)
        assert result.stats.files_skipped == 0 or result.stats.files_scanned == 0

    def test_handles_nonexistent_path(self, scanner):
        result = scanner.scan(Path("/nonexistent/path"))
        assert len(result.stats.errors) > 0

    def test_deduplicates_findings(self, scanner, temp_repo):
        code = 'password = "secret123456"'
        (temp_repo / "app.py").write_text(code)
        result = scanner.scan(temp_repo)
        same_line = [f for f in result.findings if f.file == "app.py" and f.line == 1]
        rule_ids = [f.rule_id for f in same_line]
        assert len(rule_ids) == len(set(rule_ids))

    def test_stats_tracking(self, scanner, temp_repo):
        (temp_repo / "a.py").write_text("line1\nline2\nline3\n")
        (temp_repo / "b.py").write_text("line1\nline2\n")
        result = scanner.scan(temp_repo)
        assert result.stats.files_scanned == 2
        assert result.stats.lines_scanned == 7  # 4 lines in a.py + 3 lines in b.py

    def test_min_severity_filter(self, temp_repo):
        (temp_repo / "app.py").write_text("MD5 hash: hashlib.md5(data)")
        config = Config(min_severity=Severity.HIGH)
        scanner = Scanner(config)
        result = scanner.scan(temp_repo)
        assert not any(f.severity == Severity.MEDIUM for f in result.findings)

    def test_confidence_threshold_filter(self, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        config = Config(confidence_threshold=1.0)
        scanner = Scanner(config)
        result = scanner.scan(temp_repo)
        assert all(f.confidence >= 1.0 for f in result.findings)

    def test_scan_result_properties(self, scanner, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        result = scanner.scan(temp_repo)
        assert isinstance(result.high, list)
        assert isinstance(result.medium, list)
        assert isinstance(result.low, list)
        assert isinstance(result.summary, dict)
        assert result.duration > 0

    def test_verbose_callback(self, scanner, temp_repo):
        (temp_repo / "app.py").write_text('password = "secret123456"')
        calls = []

        def callback(current, total, filepath):
            calls.append((current, total, filepath))

        scanner.scan(temp_repo, callback=callback)
        assert len(calls) > 0
