"""Main scanner that orchestrates the analysis."""

from __future__ import annotations

import time
from pathlib import Path

from xecurex.analyzers.generic_analyzer import GenericAnalyzer
from xecurex.analyzers.python_analyzer import PythonAnalyzer
from xecurex.config import Config
from xecurex.models import Finding, ScanResult, Severity
from xecurex.rules.base import load_all_rules


class Scanner:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.rules = load_all_rules()
        self.generic_analyzer = GenericAnalyzer(self.rules)
        self.python_analyzer = PythonAnalyzer(self.rules)

    def scan(self, path: Path, callback=None) -> ScanResult:
        start = time.time()
        result = ScanResult()
        path = path.resolve()

        if not path.exists():
            result.stats.errors.append(f"Path does not exist: {path}")
            return result

        files = self._collect_files(path)

        for i, filepath in enumerate(files):
            if callback:
                callback(i + 1, len(files), str(filepath.relative_to(path)))

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                result.stats.errors.append(f"Error reading {filepath}: {e}")
                result.stats.files_skipped += 1
                continue

            file_size = len(content.encode("utf-8"))
            if file_size > self.config.max_file_size:
                result.stats.files_skipped += 1
                continue

            result.stats.files_scanned += 1
            result.stats.lines_scanned += content.count("\n") + 1

            rel_path = str(filepath.relative_to(path))
            findings = self._analyze_file(content, rel_path, filepath)

            for f in findings:
                if (
                    self.config.passes_severity_filter(f.severity)
                    and f.confidence >= self.config.confidence_threshold
                ):
                    result.findings.append(f)

        result.findings = self._deduplicate(result.findings)
        result.findings.sort(key=lambda f: (list(Severity).index(f.severity), f.file, f.line))
        result.duration = time.time() - start

        return result

    def _collect_files(self, path: Path) -> list[Path]:
        files: list[Path] = []

        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue

            rel = str(file_path.relative_to(path))
            if self.config.should_exclude(rel):
                continue

            if not self.config.should_include(file_path.suffix):
                continue

            files.append(file_path)

        files.sort()
        return files

    def _analyze_file(self, content: str, rel_path: str, filepath: Path) -> list[Finding]:
        if filepath.suffix == ".py" and self.config.use_ast:
            return self.python_analyzer.analyze(content, rel_path)
        return self.generic_analyzer.analyze(content, rel_path)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, int, str]] = set()
        result: list[Finding] = []

        for f in findings:
            key = (f.file, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                result.append(f)

        return result
