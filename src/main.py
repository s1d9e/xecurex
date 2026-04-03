#!/usr/bin/env python3
"""
Red Team Security Audit Tool for GitHub Repositories
Analyzes code for common security vulnerabilities
"""

import argparse
import os
import re
from pathlib import Path
from typing import List, Dict, Optional
import json

class SecurityAuditor:
    VULNERABILITY_PATTERNS = {
        "Hardcoded Credentials": [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded password detected"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded API key detected"),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded secret detected"),
            (r'token\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Hardcoded token detected"),
            (r'aws[_-]?access', "AWS credentials in code"),
        ],
        "SQL Injection": [
            (r'execute\s*\([^)]*\+[^)]*\)', "SQL query with string concatenation"),
            (r'cursor\.execute\s*\([^)]*%s[^)]*\+', "Potential SQL injection"),
            (r'f["\'][^"\']*SELECT.*\{', "f-string SQL query"),
        ],
        "Command Injection": [
            (r'os\.system\s*\(', "os.system call - command injection risk"),
            (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', "subprocess with shell=True"),
            (r'eval\s*\(', "eval() usage - code execution risk"),
            (r'exec\s*\(', "exec() usage - code execution risk"),
        ],
        "Path Traversal": [
            (r'open\s*\([^,)]*\+[^,)]*\)', "Dynamic file path in open()"),
            (r'\.\.\/', "Path traversal pattern detected"),
            (r'readfile\s*\(', "Potential path traversal"),
        ],
        "XSS Vulnerabilities": [
            (r'innerHTML\s*=', "Dangerous innerHTML assignment"),
            (r'document\.write\s*\(', "document.write usage"),
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        ],
        "Weak Crypto": [
            (r'hashlib\.md5\s*\(', "MD5 hash usage - weak cryptographic"),
            (r'hashlib\.sha1\s*\(', "SHA1 hash usage - weak cryptographic"),
            (r'hashlib\.new\s*\(', "Weak hash algorithm via hashlib.new"),
            (r'Crypto\.Cipher', "Weak cipher usage"),
        ],
        "Insecure Deserialization": [
            (r'pickle\.load(s)?\s*\(', "Pickle deserialization - insecure"),
            (r'yaml\.load\s*\(', "Unsafe YAML load - use yaml.safe_load"),
            (r'yaml\.unsafe_load\s*\(', "Unsafe YAML load"),
            (r'unserialize\s*\(', "PHP unserialize - insecure"),
        ],
        "Sensitive Data Exposure": [
            (r'console\.log\s*\([^)]*(?:password|secret|token|key)', "Sensitive data in console.log"),
            (r'print\s*\(.*(?:password|secret|token|key)', "Sensitive data in print"),
        ],
        "Hardcoded IP/URL": [
            (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Hardcoded IP address"),
            (r'http://[^"\']{20,}', "Insecure HTTP URL"),
        ],
        "Insecure Dependencies": [
            (r'require\s*\(\s*["\']crypto["\']', "Node crypto usage"),
            (r'import\s+jwt', "JWT library usage"),
        ],
    }

    def __init__(self, repo_path: str, output_format: str = "text", exclude_dirs: Optional[List[str]] = None):
        self.repo_path = Path(repo_path).resolve()
        self.output_format = output_format
        self.exclude_dirs = exclude_dirs or ['node_modules', '.git', '__pycache__', 'venv', '.venv', 'vendor', 'dist', 'build']
        self.vulnerabilities = []
        self.stats = {"files_scanned": 0, "lines_scanned": 0}
        
    def scan(self) -> List[Dict]:
        if not self.repo_path.exists():
            print(f"[-] Error: Path does not exist: {self.repo_path}")
            return []
            
        print(f"[+] Scanning repository: {self.repo_path}")
        
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go', '.sh', '.cs', '.csproj', '.sql'}
        
        for file_path in self.repo_path.rglob('*'):
            if not file_path.is_file():
                continue
                
            if any(excluded in str(file_path) for excluded in self.exclude_dirs):
                continue
                
            if file_path.suffix not in extensions:
                continue
                
            self._scan_file(file_path)
            
        return self.vulnerabilities
    
    def _scan_file(self, file_path: Path):
        try:
            content = file_path.read_text(errors='ignore')
            self.stats["files_scanned"] += 1
            self.stats["lines_scanned"] += len(content.split('\n'))
            
            for category, rules in self.VULNERABILITY_PATTERNS.items():
                for pattern, desc in rules:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        self.vulnerabilities.append({
                            'file': str(file_path.relative_to(self.repo_path)),
                            'category': category,
                            'description': desc,
                            'line': line_num,
                            'severity': self._get_severity(category),
                            'match': match.group()[:50]
                        })
        except Exception as e:
            print(f"[-] Error scanning {file_path}: {e}")
    
    def _get_severity(self, category: str) -> str:
        high = ["Hardcoded Credentials", "Command Injection", "SQL Injection", "Insecure Deserialization"]
        medium = ["XSS Vulnerabilities", "Path Traversal", "Weak Crypto"]
        low = ["Sensitive Data Exposure", "Hardcoded IP/URL", "Insecure Dependencies"]
        
        if category in high:
            return "HIGH"
        elif category in medium:
            return "MEDIUM"
        return "LOW"
    
    def _print_text_report(self):
        print("\n" + "="*70)
        print("                    SECURITY AUDIT REPORT")
        print("="*70)
        
        print(f"\n📊 Statistics:")
        print(f"   Files scanned: {self.stats['files_scanned']}")
        print(f"   Lines scanned: {self.stats['lines_scanned']}")
        
        if not self.vulnerabilities:
            print("\n[✓] No vulnerabilities detected!")
            return
            
        print(f"\n[!] Found {len(self.vulnerabilities)} potential security issues:\n")
        
        by_severity = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for v in self.vulnerabilities:
            by_severity[v['severity']].append(v)
        
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            if by_severity[severity]:
                print(f"\n{'🔴' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🟢'} {severity} Severity ({len(by_severity[severity])})")
                print("-" * 50)
                for vuln in by_severity[severity]:
                    print(f"  📁 {vuln['file']}:{vuln['line']}")
                    print(f"     [{vuln['category']}] {vuln['description']}")
                    print()

    def _print_json_report(self):
        report = {
            "repository": str(self.repo_path),
            "stats": self.stats,
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "total": len(self.vulnerabilities),
                "high": sum(1 for v in self.vulnerabilities if v['severity'] == "HIGH"),
                "medium": sum(1 for v in self.vulnerabilities if v['severity'] == "MEDIUM"),
                "low": sum(1 for v in self.vulnerabilities if v['severity'] == "LOW"),
            }
        }
        print(json.dumps(report, indent=2))
    
    def report(self):
        if self.output_format == "json":
            self._print_json_report()
        else:
            self._print_text_report()


def main():
    parser = argparse.ArgumentParser(
        description='Red Team Security Audit Tool - Scan repositories for vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py /path/to/repo
  python main.py /path/to/repo --format json
  python main.py /path/to/repo --output report.json --format json
        """
    )
    parser.add_argument('path', help='Path to repository to scan')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--exclude', nargs='*', help='Additional directories to exclude')
    
    args = parser.parse_args()
    
    auditor = SecurityAuditor(args.path, args.format, args.exclude)
    auditor.scan()
    auditor.report()
    
    if args.output:
        with open(args.output, 'w') as f:
            import json
            json.dump({
                "stats": auditor.stats,
                "vulnerabilities": auditor.vulnerabilities
            }, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()