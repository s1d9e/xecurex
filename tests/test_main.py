"""Tests for the python -m xecurex entry point."""

import subprocess
import sys


def test_module_exit_code_on_findings(temp_repo):
    (temp_repo / "app.py").write_text('password = "secret123456"')
    proc = subprocess.run(
        [sys.executable, "-m", "xecurex", str(temp_repo)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1
    assert "SECURITY AUDIT REPORT" in proc.stdout


def test_module_exit_code_clean(temp_repo):
    (temp_repo / "app.py").write_text("x = 1\n")
    proc = subprocess.run(
        [sys.executable, "-m", "xecurex", str(temp_repo)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0


def test_module_version():
    proc = subprocess.run(
        [sys.executable, "-m", "xecurex", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "2.1.0" in proc.stdout
