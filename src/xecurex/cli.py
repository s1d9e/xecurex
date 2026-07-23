"""CLI entry point for XecureX."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from xecurex import __version__
from xecurex.config import Config, load_config
from xecurex.models import Severity
from xecurex.reporter import report_json, report_text
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
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Write results to file instead of stdout")
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument("--exclude", nargs="*", help="Additional directories to exclude")
    parser.add_argument(
        "--no-ast", action="store_true", help="Disable Python AST analysis (regex only)"
    )
    parser.add_argument("--no-config", action="store_true", help="Ignore xecurex.toml config file")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.3,
        help="Minimum confidence threshold 0.0-1.0 (default: 0.3)",
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

    config.min_severity = Severity(args.min_severity.upper())
    config.use_ast = not args.no_ast
    config.confidence_threshold = args.min_confidence

    if args.exclude:
        config.exclude_dirs.extend(args.exclude)

    scanner = Scanner(config)
    callback = _verbose_callback(args.verbose)

    result = scanner.scan(repo_path, callback=callback)

    if args.verbose and result.stats.files_scanned > 0:
        print()

    if args.format == "json":
        if args.output:
            with open(args.output, "w") as f:
                report_json(result, file=f)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            report_json(result)
    else:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                report_text(result, file=f)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            report_text(result)

    if result.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
