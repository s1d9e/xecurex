"""CLI entry point for XecureX."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from xecurex import __version__
from xecurex.config import Config, load_config
from xecurex.models import ScanResult, Severity
from xecurex.reporter import report_json, report_sarif, report_text
from xecurex.scanner import Scanner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xecurex",
        description="XecureX — Security Audit Tool for Source Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  xecurex /path/to/repo
  xecurex /path/to/repo --format json --output report.json
  xecurex /path/to/repo --min-severity high
  xecurex /path/to/repo --exclude tests/ docs/
  xecurex /path/to/repo --no-ast --verbose
""",
    )
    parser.add_argument("path", help="Path to directory or repository to scan")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Write results to file instead of stdout")
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Suppress findings listed in a previous report "
        "(JSON report or 'file:line:rule_id' text file)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default=None,
        help="Minimum severity to report (default: from config file, or low)",
    )
    parser.add_argument("--exclude", nargs="*", help="Additional directories to exclude")
    parser.add_argument(
        "--ast",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable Python AST analysis (default: from config file)",
    )
    parser.add_argument("--no-config", action="store_true", help="Ignore xecurex.toml config file")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="Minimum confidence threshold 0.0-1.0 (default: from config file, or 0.3)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show verbose output during scan"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _verbose_callback(verbose: bool):
    if not verbose:
        return None

    def callback(current: int, total: int, filepath: str) -> None:
        pct = current / total * 100 if total > 0 else 0
        print(f"\r  Scanning [{current}/{total}] {pct:.0f}% — {filepath:<50}", end="", flush=True)

    return callback


def _load_baseline(path: str) -> set[tuple[str, int, str]] | None:
    """Load known findings from a baseline file.

    Accepts a previous JSON report (``{"findings": [...]}`` or a bare list)
    or a text file with one ``file:line:rule_id`` entry per line.
    Returns None when the file cannot be read.
    """
    baseline_path = Path(path)
    try:
        text = baseline_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read baseline file: {exc}", file=sys.stderr)
        return None

    entries: set[tuple[str, int, str]] = set()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        items = data.get("findings", [])
    elif isinstance(data, list):
        items = data
    else:
        items = None

    if items is not None:
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                entries.add((str(item["file"]), int(item["line"]), str(item["rule_id"])))
            except (KeyError, TypeError, ValueError):
                continue
        return entries

    # Text fallback: one "file:line:rule_id" entry per line.
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        file_part, line_part, rule_part = parts
        try:
            entries.add((file_part, int(line_part), rule_part))
        except ValueError:
            continue
    return entries


def _apply_baseline(result: ScanResult, baseline: set[tuple[str, int, str]]) -> None:
    result.findings = [f for f in result.findings if (f.file, f.line, f.rule_id) not in baseline]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    repo_path = Path(args.path).resolve()
    if not repo_path.exists():
        print(f"Error: path does not exist: {repo_path}", file=sys.stderr)
        return 2

    if not repo_path.is_dir():
        print(f"Error: path is not a directory: {repo_path}", file=sys.stderr)
        return 2

    config = load_config(repo_path) if not args.no_config else Config()

    # CLI flags only override the config when explicitly provided.
    if args.min_severity is not None:
        config.min_severity = Severity(args.min_severity.upper())
    if args.ast is not None:
        config.use_ast = args.ast
    if args.min_confidence is not None:
        config.confidence_threshold = args.min_confidence

    if args.exclude:
        config.exclude_dirs.extend(args.exclude)

    scanner = Scanner(config)
    callback = _verbose_callback(args.verbose)

    result = scanner.scan(repo_path, callback=callback)

    if args.verbose and result.stats.files_scanned > 0:
        print()

    if args.baseline:
        baseline = _load_baseline(args.baseline)
        if baseline is None:
            return 2
        _apply_baseline(result, baseline)

    reporters = {"text": report_text, "json": report_json, "sarif": report_sarif}
    report = reporters[args.format]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            report(result, file=f)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        report(result)

    if result.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
