"""Report generation in text, JSON and SARIF formats."""

from __future__ import annotations

import hashlib
import json
import sys

from colorama import Fore, Style, init

from xecurex import __version__
from xecurex.models import ScanResult, Severity

init(autoreset=True)

SEVERITY_COLORS = {
    Severity.HIGH: Fore.RED,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.GREEN,
}

SEVERITY_ICONS = {
    Severity.HIGH: "!!!",
    Severity.MEDIUM: " ! ",
    Severity.LOW: " i ",
}


def report_text(result: ScanResult, file=None) -> None:
    out = file or sys.stdout

    def w(s: str) -> None:
        print(s, file=out)

    w("")
    w("=" * 70)
    w("                    SECURITY AUDIT REPORT")
    w("=" * 70)

    w(f"\n  Files scanned:  {result.stats.files_scanned}")
    w(f"  Lines scanned:  {result.stats.lines_scanned}")
    w(f"  Files skipped:  {result.stats.files_skipped}")
    w(f"  Scan duration:  {result.duration:.2f}s")

    if result.stats.errors:
        w(f"\n  Errors: {len(result.stats.errors)}")
        for err in result.stats.errors[:5]:
            w(f"    - {err}")

    if not result.findings:
        w(f"\n  {Fore.GREEN}No security issues detected.{Style.RESET_ALL}")
        w("")
        return

    summary = result.summary
    w(f"\n  Found {summary['total']} potential security issues:")
    w(
        f"    {Fore.RED}HIGH: {summary['high']}{Style.RESET_ALL}  "
        f"{Fore.YELLOW}MEDIUM: {summary['medium']}{Style.RESET_ALL}  "
        f"{Fore.GREEN}LOW: {summary['low']}{Style.RESET_ALL}"
    )

    for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = [f for f in result.findings if f.severity == severity]
        if not findings:
            continue

        color = SEVERITY_COLORS[severity]
        w(
            f"\n  {color}{SEVERITY_ICONS[severity]} {severity.value} Severity ({len(findings)}){Style.RESET_ALL}"
        )
        w("  " + "-" * 50)

        for vuln in findings:
            conf_bar = _confidence_bar(vuln.confidence)
            w(f"    {vuln.file}:{vuln.line}")
            w(f"      [{vuln.rule_id}] {vuln.description}")
            w(f"      Confidence: {conf_bar} ({vuln.confidence:.0%})")
            if vuln.match:
                w(f"      Code: {vuln.match[:60]}")
            w("")

    w("=" * 70)


def report_json(result: ScanResult, file=None) -> None:
    out = file or sys.stdout
    data = result.to_dict()
    print(json.dumps(data, indent=2, default=str), file=out)


# SARIF levels and GitHub code-scanning security severities.
_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY = {
    Severity.HIGH: "8.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


def report_sarif(result: ScanResult, file=None) -> None:
    """Write results as a SARIF 2.1.0 document.

    Compatible with GitHub Code Scanning / `github/codeql-action/upload-sarif`.
    """
    out = file or sys.stdout
    print(json.dumps(_to_sarif(result), indent=2, default=str), file=out)


def _to_sarif(result: ScanResult) -> dict:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.description},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "category": f.category,
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "confidence": f.confidence,
                },
            }

        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column + 1,  # SARIF is 1-based
                                "snippet": {"text": f.match[:120]},
                            },
                        }
                    }
                ],
                # Line-independent fingerprint: alerts stay matched even when
                # code moves around between scans.
                "partialFingerprints": {
                    "primaryLocationLineHash": hashlib.sha256(
                        f"{f.rule_id}|{f.file}|{f.match}".encode()
                    ).hexdigest()[:32]
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "XecureX",
                        "version": __version__,
                        "informationUri": "https://github.com/s1d9e/xecurex",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _confidence_bar(confidence: float) -> str:
    filled = int(confidence * 10)
    return "[" + "#" * filled + "." * (10 - filled) + "]"
