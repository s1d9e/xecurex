import pytest
import tempfile
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
from main import SecurityAuditor


class TestSecurityAuditor:
    @pytest.fixture
    def temp_repo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_scan_finds_hardcoded_password(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('password = "secret123"')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert any(v['category'] == 'Hardcoded Credentials' for v in auditor.vulnerabilities)
    
    def test_scan_finds_command_injection(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('import os\nos.system("ls")')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert any(v['category'] == 'Command Injection' for v in auditor.vulnerabilities)
    
    def test_scan_finds_sql_injection(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert any(v['category'] == 'SQL Injection' for v in auditor.vulnerabilities)
    
    def test_scan_finds_eval(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('eval(user_input)')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert any(v['category'] == 'Command Injection' and 'eval' in v['description'].lower() for v in auditor.vulnerabilities)
    
    def test_scan_finds_pickle(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('import pickle\ndata = pickle.load(file)')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert any(v['category'] == 'Insecure Deserialization' for v in auditor.vulnerabilities)
    
    def test_exclude_directories(self, temp_repo):
        node_modules = Path(temp_repo) / "node_modules" / "test.js"
        node_modules.parent.mkdir(parents=True)
        node_modules.write_text('password = "secret"')
        
        source_file = Path(temp_repo) / "app.js"
        source_file.write_text('password = "secret"')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert not any('node_modules' in v['file'] for v in auditor.vulnerabilities)
        assert any('app.js' in v['file'] for v in auditor.vulnerabilities)
    
    def test_nonexistent_path(self):
        auditor = SecurityAuditor("/nonexistent/path")
        result = auditor.scan()
        
        assert result == []
    
    def test_stats_tracking(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('line1\nline2\nline3\n')
        
        auditor = SecurityAuditor(temp_repo)
        auditor.scan()
        
        assert auditor.stats["files_scanned"] == 1
        assert auditor.stats["lines_scanned"] >= 3
    
    def test_json_output_format(self, temp_repo):
        test_file = Path(temp_repo) / "test.py"
        test_file.write_text('password = "secret"')
        
        auditor = SecurityAuditor(temp_repo, output_format="json")
        auditor.scan()
        auditor.report()
        
        assert auditor.output_format == "json"