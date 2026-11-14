"""Generic regex-based analyzer for all languages."""

from __future__ import annotations

from pathlib import Path

from xecurex.models import Finding
from xecurex.rules.base import Rule

# Comment tokens per language suffix.
_LINE_COMMENT_TOKENS: dict[str, tuple[str, ...]] = {
    ".py": ("#",),
    ".sh": ("#",),
    ".rb": ("#",),
    ".php": ("#", "//"),
    ".sql": ("--", "#"),
    ".js": ("//",),
    ".ts": ("//",),
    ".jsx": ("//",),
    ".tsx": ("//",),
    ".java": ("//",),
    ".go": ("//",),
    ".cs": ("//",),
}

_BLOCK_COMMENT_TOKENS: dict[str, tuple[str, str]] = {
    ".js": ("/*", "*/"),
    ".ts": ("/*", "*/"),
    ".jsx": ("/*", "*/"),
    ".tsx": ("/*", "*/"),
    ".java": ("/*", "*/"),
    ".go": ("/*", "*/"),
    ".cs": ("/*", "*/"),
    ".php": ("/*", "*/"),
    ".sql": ("/*", "*/"),
}


def strip_comments(content: str, filepath: str) -> str:
    """Blank out comments and docstrings.

    Line numbers and column positions are preserved: comment characters are
    replaced with spaces (or the line is emptied) instead of being removed,
    so findings computed on the stripped content keep accurate locations.
    """
    suffix = Path(filepath).suffix
    if suffix == ".py":
        return _strip_python(content)

    line_tokens = _LINE_COMMENT_TOKENS.get(suffix)
    block_tokens = _BLOCK_COMMENT_TOKENS.get(suffix)
    if line_tokens is None and block_tokens is None:
        return content

    return _strip_lines(content, line_tokens or (), block_tokens)


def _strip_python(content: str) -> str:
    """Strip Python comments and docstrings, preserving layout."""
    out: list[str] = []
    doc_delim: str | None = None

    for line in content.split("\n"):
        stripped = line.lstrip()

        if doc_delim is not None:
            # Inside a docstring: blank the line, keep the line count.
            out.append("")
            if doc_delim in line:
                doc_delim = None
            continue

        if stripped.startswith(('"""', "'''")):
            delim = stripped[:3]
            if len(stripped) > 3 and stripped.count(delim) >= 2:
                # Single-line docstring.
                out.append("")
                continue
            doc_delim = delim
            out.append("")
            continue

        new_line, _ = _blank_line_comments(line, ("#",), None)
        out.append(new_line)

    return "\n".join(out)


def _strip_lines(
    content: str,
    line_tokens: tuple[str, ...],
    block_tokens: tuple[str, str] | None,
) -> str:
    """Strip line and block comments, preserving layout."""
    out: list[str] = []
    in_block = False

    for line in content.split("\n"):
        if in_block:
            assert block_tokens is not None
            end = line.find(block_tokens[1])
            if end == -1:
                out.append("")
                continue
            # Blank the comment part, then process whatever follows it.
            consumed = end + len(block_tokens[1])
            rest, in_block = _blank_line_comments(line[consumed:], line_tokens, block_tokens)
            out.append(" " * consumed + rest)
            continue

        new_line, in_block = _blank_line_comments(line, line_tokens, block_tokens)
        out.append(new_line)

    return "\n".join(out)


def _blank_line_comments(
    line: str,
    line_tokens: tuple[str, ...],
    block_tokens: tuple[str, str] | None,
) -> tuple[str, bool]:
    """Blank comments in a single line, quote-aware.

    Returns ``(new_line, in_block_comment)`` where ``in_block_comment`` is
    True when an unterminated block comment starts on this line.
    """
    n = len(line)
    out: list[str] = []
    quote: str | None = None
    i = 0

    while i < n:
        ch = line[i]

        if quote is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch in "\"'`":
            quote = ch
            out.append(ch)
            i += 1
            continue

        if block_tokens is not None and line.startswith(block_tokens[0], i):
            end = line.find(block_tokens[1], i + len(block_tokens[0]))
            if end == -1:
                # Unterminated block comment: blank until end of line.
                return "".join(out) + " " * (n - i), True
            out.extend(" " * (end + len(block_tokens[1]) - i))
            i = end + len(block_tokens[1])
            continue

        if any(line.startswith(tok, i) for tok in line_tokens):
            # Line comment: blank until end of line, keep columns.
            return "".join(out) + " " * (n - i), False

        out.append(ch)
        i += 1

    return "".join(out), False


class GenericAnalyzer:
    """Regex-based analyzer that works with any language."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def analyze(self, content: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        stripped = strip_comments(content, filepath)

        for rule in self.rules:
            if rule.language is not None:
                continue
            findings.extend(rule.check(stripped, filepath))

        return findings
