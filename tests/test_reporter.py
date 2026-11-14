"""Tests for report generation."""

import io
import json

from xecurex.models import Finding, ScanResult, ScanStats, Severity
from xecurex.reporter import report_json, report_sarif, report_text


def make_finding(**overrides) -> Finding:
    defaults = dict(
        file="app.py",
        line=1,
        column=0,
        category="Injection",
        description="os.system() call — command injection risk",
        severity=Severity.HIGH,
        rule_id="INJECT-005",
        match='os.system("ls")',
        confidence=0.9,
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestReportText:
    def test_empty_report(self):
        result = ScanResult()
        buf = io.StringIO()
        report_text(result, file=buf)
        out = buf.getvalue()
        assert "SECURITY AUDIT REPORT" in out
        assert "No security issues detected" in out

    def test_report_contains_findings(self):
        result = ScanResult(
            findings=[make_finding()],
            stats=ScanStats(files_scanned=1, lines_scanned=10),
        )
        buf = io.StringIO()
        report_text(result, file=buf)
        out = buf.getvalue()
        assert "Files scanned:  1" in out
        assert "Found 1 potential security issues" in out
        assert "HIGH Severity (1)" in out
        assert "[INJECT-005]" in out
        assert "app.py:1" in out
        assert 'os.system("ls")' in out

    def test_report_groups_by_severity(self):
        findings = [
            make_finding(),
            make_finding(severity=Severity.MEDIUM, rule_id="CRYPTO-001", line=2),
            make_finding(severity=Severity.LOW, rule_id="EXPOSE-001", line=3),
        ]
        result = ScanResult(findings=findings)
        buf = io.StringIO()
        report_text(result, file=buf)
        out = buf.getvalue()
        assert "HIGH Severity (1)" in out
        assert "MEDIUM Severity (1)" in out
        assert "LOW Severity (1)" in out

    def test_errors_shown_even_without_findings(self):
        result = ScanResult(stats=ScanStats(errors=["Path does not exist: /x"]))
        buf = io.StringIO()
        report_text(result, file=buf)
        out = buf.getvalue()
        assert "Errors: 1" in out
        assert "Path does not exist" in out

    def test_summary_counts_match_findings(self):
        findings = [
            make_finding(),
            make_finding(severity=Severity.MEDIUM, rule_id="CRYPTO-001", line=2),
            make_finding(severity=Severity.MEDIUM, rule_id="CRYPTO-002", line=3),
        ]
        result = ScanResult(findings=findings)
        buf = io.StringIO()
        report_text(result, file=buf)
        out = buf.getvalue()
        assert "Found 3 potential security issues" in out
        assert "MEDIUM Severity (2)" in out


class TestReportJson:
    def test_json_structure(self):
        result = ScanResult(
            findings=[make_finding()],
            stats=ScanStats(files_scanned=2, lines_scanned=42),
            duration=1.5,
        )
        buf = io.StringIO()
        report_json(result, file=buf)
        data = json.loads(buf.getvalue())

        assert data["summary"]["total"] == 1
        assert data["summary"]["high"] == 1
        assert data["stats"]["files_scanned"] == 2
        assert data["stats"]["lines_scanned"] == 42
        assert data["duration_seconds"] == 1.5

        finding = data["findings"][0]
        assert finding["rule_id"] == "INJECT-005"
        assert finding["severity"] == "HIGH"
        assert finding["file"] == "app.py"
        assert finding["line"] == 1
        assert finding["confidence"] == 0.9

    def test_severity_serialized_as_string(self):
        result = ScanResult(
            findings=[
                make_finding(),
                make_finding(severity=Severity.LOW, rule_id="EXPOSE-001", line=2),
            ]
        )
        buf = io.StringIO()
        report_json(result, file=buf)
        data = json.loads(buf.getvalue())
        severities = [f["severity"] for f in data["findings"]]
        assert severities == ["HIGH", "LOW"]

    def test_empty_result_json(self):
        result = ScanResult()
        buf = io.StringIO()
        report_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["findings"] == []
        assert data["summary"]["total"] == 0


class TestReportSarif:
    def test_sarif_document_structure(self):
        result = ScanResult(findings=[make_finding()])
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())

        assert data["version"] == "2.1.0"
        assert "sarif-2.1.0" in data["$schema"]
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "XecureX"
        assert run["tool"]["driver"]["informationUri"].endswith("xecurex")

    def test_sarif_rules_are_registered(self):
        result = ScanResult(
            findings=[
                make_finding(),
                make_finding(severity=Severity.MEDIUM, rule_id="CRYPTO-001", line=2),
            ]
        )
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids == ["INJECT-005", "CRYPTO-001"]
        assert rules[0]["defaultConfiguration"]["level"] == "error"
        assert rules[1]["defaultConfiguration"]["level"] == "warning"
        assert rules[0]["properties"]["security-severity"] == "8.5"

    def test_sarif_results_have_locations(self):
        result = ScanResult(findings=[make_finding(column=7)])
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())
        entry = data["runs"][0]["results"][0]

        assert entry["ruleId"] == "INJECT-005"
        assert entry["level"] == "error"
        location = entry["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "app.py"
        # SARIF columns are 1-based.
        assert location["region"]["startLine"] == 1
        assert location["region"]["startColumn"] == 8

    def test_sarif_level_mapping(self):
        findings = [
            make_finding(),
            make_finding(severity=Severity.MEDIUM, rule_id="CRYPTO-001", line=2),
            make_finding(severity=Severity.LOW, rule_id="EXPOSE-001", line=3),
        ]
        result = ScanResult(findings=findings)
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())
        levels = [r["level"] for r in data["runs"][0]["results"]]
        assert levels == ["error", "warning", "note"]

    def test_sarif_fingerprint_is_line_independent(self):
        result = ScanResult(findings=[make_finding(line=10)])
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())
        fingerprint = data["runs"][0]["results"][0]["partialFingerprints"]
        assert "primaryLocationLineHash" in fingerprint

    def test_sarif_empty_result(self):
        result = ScanResult()
        buf = io.StringIO()
        report_sarif(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []
