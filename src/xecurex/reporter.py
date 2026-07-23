"""Report generation in text and JSON formats."""

from __future__ import annotations

import json
import sys

from colorama import Fore, Style, init

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


def _confidence_bar(confidence: float) -> str:
    filled = int(confidence * 10)
    return "[" + "#" * filled + "." * (10 - filled) + "]"
