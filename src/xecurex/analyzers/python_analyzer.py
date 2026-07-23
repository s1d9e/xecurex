"""Python AST-based analyzer for precise vulnerability detection."""

from __future__ import annotations

import ast
import re

from xecurex.models import Finding, Severity
from xecurex.rules.base import Rule

# Dangerous function calls mapped to (category, severity, description, rule_id)
_DANGEROUS_CALLS = {
    "os.system": (
        "Injection",
        Severity.HIGH,
        "os.system() — command injection risk",
        "INJECT-AST-001",
    ),
    "os.popen": (
        "Injection",
        Severity.HIGH,
        "os.popen() — command injection risk",
        "INJECT-AST-002",
    ),
    "eval": (
        "Injection",
        Severity.HIGH,
        "eval() — arbitrary code execution risk",
        "INJECT-AST-003",
    ),
    "exec": (
        "Injection",
        Severity.HIGH,
        "exec() — arbitrary code execution risk",
        "INJECT-AST-004",
    ),
    "compile": (
        "Injection",
        Severity.MEDIUM,
        "compile() usage — verify input is trusted",
        "INJECT-AST-005",
    ),
    "pickle.load": (
        "Insecure Deserialization",
        Severity.HIGH,
        "pickle.load() — arbitrary code execution risk",
        "DESERN-AST-001",
    ),
    "pickle.loads": (
        "Insecure Deserialization",
        Severity.HIGH,
        "pickle.loads() — arbitrary code execution risk",
        "DESERN-AST-002",
    ),
    "yaml.load": (
        "Insecure Deserialization",
        Severity.HIGH,
        "yaml.load() without Loader — use yaml.safe_load()",
        "DESERN-AST-003",
    ),
    "yaml.unsafe_load": (
        "Insecure Deserialization",
        Severity.HIGH,
        "yaml.unsafe_load() — arbitrary code execution risk",
        "DESERN-AST-004",
    ),
    "shelve.open": (
        "Insecure Deserialization",
        Severity.MEDIUM,
        "shelve.open() uses pickle under the hood",
        "DESERN-AST-005",
    ),
    "hashlib.md5": (
        "Weak Cryptography",
        Severity.MEDIUM,
        "MD5 hash — weak, use SHA-256+",
        "CRYPTO-AST-001",
    ),
    "hashlib.sha1": (
        "Weak Cryptography",
        Severity.MEDIUM,
        "SHA-1 hash — weak, use SHA-256+",
        "CRYPTO-AST-002",
    ),
    "telnetlib.Telnet": (
        "Insecure Dependencies",
        Severity.MEDIUM,
        "telnetlib — unencrypted protocol",
        "DEP-AST-001",
    ),
    "commands.getoutput": (
        "Injection",
        Severity.HIGH,
        "commands.getoutput() — command injection risk",
        "INJECT-AST-006",
    ),
}

# Dangerous imports
_DANGEROUS_IMPORTS = {
    "pickle": (
        "Insecure Deserialization",
        Severity.MEDIUM,
        "pickle module imported — risk if deserializing untrusted data",
        "DESERN-AST-010",
    ),
    "shelve": (
        "Insecure Deserialization",
        Severity.MEDIUM,
        "shelve module imported — uses pickle under the hood",
        "DESERN-AST-011",
    ),
    "telnetlib": (
        "Insecure Dependencies",
        Severity.MEDIUM,
        "telnetlib module imported — unencrypted protocol",
        "DEP-AST-010",
    ),
    "marshal": (
        "Insecure Deserialization",
        Severity.HIGH,
        "marshal module imported — arbitrary code execution risk",
        "DESERN-AST-012",
    ),
}

# Variable names that suggest hardcoded credentials
_SENSITIVE_VAR_NAMES = re.compile(
    r"^(?:password|passwd|pwd|api_?key|secret|token|auth_?token|access_?key|private_?key|aws_?access)$",
    re.IGNORECASE,
)

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|api[_-]?key|secret|token|auth[_-]?token|access[_-]?key)\s*=\s*(["'])(?:(?!\1).){8,}\1""",
    re.IGNORECASE,
)


class PythonAnalyzer:
    """AST-based analyzer for Python files with regex fallback."""

    def __init__(self, regex_rules: list[Rule]) -> None:
        self.regex_rules = regex_rules

    def analyze(self, content: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            tree = ast.parse(content)
            findings.extend(self._check_ast(tree, filepath, content))
        except SyntaxError:
            pass

        findings.extend(self._check_regex_fallback(content, filepath))

        return findings

    def _check_ast(self, tree: ast.Module, filepath: str, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, filepath))
            elif isinstance(node, ast.Import):
                findings.extend(self._check_import(node, filepath))
            elif isinstance(node, ast.ImportFrom):
                findings.extend(self._check_import_from(node, filepath))
            elif isinstance(node, ast.Assign):
                findings.extend(self._check_assignment(node, filepath))

        return findings

    def _check_call(self, node: ast.Call, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        call_name = self._get_call_name(node)

        if call_name in _DANGEROUS_CALLS:
            category, severity, description, rule_id = _DANGEROUS_CALLS[call_name]

            if call_name == "yaml.load":
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        break
                else:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            category=category,
                            description=description,
                            severity=severity,
                            rule_id=rule_id,
                            match=f"{call_name}()",
                            confidence=0.9,
                        )
                    )
            else:
                findings.append(
                    Finding(
                        file=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        category=category,
                        description=description,
                        severity=severity,
                        rule_id=rule_id,
                        match=f"{call_name}()",
                        confidence=0.95,
                    )
                )

        if (
            call_name == "subprocess.run"
            or call_name == "subprocess.call"
            or call_name == "subprocess.Popen"
        ):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            category="Injection",
                            severity=Severity.HIGH,
                            description=f"{call_name}() with shell=True — command injection risk",
                            rule_id="INJECT-AST-007",
                            match=f"{call_name}(shell=True)",
                            confidence=0.95,
                        )
                    )

        return findings

    def _check_import(self, node: ast.Import, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        for alias in node.names:
            module = alias.name.split(".")[0]
            if module in _DANGEROUS_IMPORTS:
                category, severity, description, rule_id = _DANGEROUS_IMPORTS[module]
                findings.append(
                    Finding(
                        file=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        category=category,
                        severity=severity,
                        description=description,
                        rule_id=rule_id,
                        match=f"import {alias.name}",
                        confidence=0.7,
                    )
                )
        return findings

    def _check_import_from(self, node: ast.ImportFrom, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if node.module:
            module = node.module.split(".")[0]
            if module in _DANGEROUS_IMPORTS:
                category, severity, description, rule_id = _DANGEROUS_IMPORTS[module]
                names = ", ".join(a.name for a in node.names)
                findings.append(
                    Finding(
                        file=filepath,
                        line=node.lineno,
                        column=node.col_offset,
                        category=category,
                        severity=severity,
                        description=description,
                        rule_id=rule_id,
                        match=f"from {node.module} import {names}",
                        confidence=0.7,
                    )
                )
        return findings

    def _check_assignment(self, node: ast.Assign, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and _SENSITIVE_VAR_NAMES.match(target.id)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                value = node.value.value
                if len(value) >= 8 and not value.startswith(("{", "<", "os.", "env")):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            column=node.col_offset,
                            category="Hardcoded Credentials",
                            severity=Severity.HIGH,
                            description=f"Hardcoded value assigned to '{target.id}'",
                            rule_id="CRED-AST-001",
                            match=f'{target.id} = "{value[:30]}..."',
                            confidence=0.85,
                        )
                    )
        return findings

    def _check_regex_fallback(self, content: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.regex_rules:
            if rule.language is not None and rule.language != "python":
                continue
            findings.extend(rule.check(content, filepath))
        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""
