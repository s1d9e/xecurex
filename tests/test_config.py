"""Tests for configuration loading and path exclusions."""

from xecurex.config import Config, load_config
from xecurex.models import Severity


class TestShouldExclude:
    def setup_method(self):
        self.config = Config()

    def test_excludes_node_modules_component(self):
        assert self.config.should_exclude("node_modules/pkg/index.js")

    def test_excludes_git_dir(self):
        assert self.config.should_exclude(".git/config")

    def test_excludes_glob_component(self):
        assert self.config.should_exclude("mypackage.egg-info/setup.py")

    def test_does_not_exclude_by_substring(self):
        # "build" must not match "mybuild"
        assert not self.config.should_exclude("mybuild/output.js")

    def test_does_not_exclude_github_for_git_pattern(self):
        # ".git" must not match ".github"
        assert not self.config.should_exclude(".github/workflows/ci.yml")

    def test_excludes_path_prefix(self):
        self.config.exclude_dirs.append("src/generated")
        assert self.config.should_exclude("src/generated/api.py")
        assert not self.config.should_exclude("src/gen/api.py")

    def test_pattern_with_trailing_slash(self):
        self.config.exclude_dirs.append("tests/")
        assert self.config.should_exclude("tests/test_foo.py")

    def test_custom_glob_pattern(self):
        self.config.exclude_dirs.append("*.min.js")
        assert self.config.should_exclude("dist/app.min.js")

    def test_empty_pattern_is_ignored(self):
        self.config.exclude_dirs.append("")
        assert not self.config.should_exclude("anything.py")


class TestLoadConfig:
    def test_defaults_without_config_file(self, temp_repo):
        config = load_config(temp_repo)
        assert config.min_severity == Severity.LOW
        assert config.use_ast is True
        assert config.confidence_threshold == 0.3

    def test_loads_xecurex_toml(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text('[xecurex]\nmin_severity = "high"\n')
        config = load_config(temp_repo)
        assert config.min_severity == Severity.HIGH

    def test_loads_pyproject_section(self, temp_repo):
        (temp_repo / "pyproject.toml").write_text(
            '[tool.xecurex]\nmin_severity = "medium"\nuse_ast = false\n'
        )
        config = load_config(temp_repo)
        assert config.min_severity == Severity.MEDIUM
        assert config.use_ast is False

    def test_xecurex_toml_takes_precedence(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text('[xecurex]\nmin_severity = "high"\n')
        (temp_repo / "pyproject.toml").write_text('[tool.xecurex]\nmin_severity = "low"\n')
        config = load_config(temp_repo)
        assert config.min_severity == Severity.HIGH

    def test_file_without_section_falls_through(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text("[other]\nvalue = 1\n")
        (temp_repo / "pyproject.toml").write_text('[tool.xecurex]\nmin_severity = "high"\n')
        config = load_config(temp_repo)
        assert config.min_severity == Severity.HIGH

    def test_invalid_toml_warns_and_uses_defaults(self, temp_repo, capsys):
        (temp_repo / "xecurex.toml").write_text("not [ valid toml")
        config = load_config(temp_repo)
        assert config.min_severity == Severity.LOW
        captured = capsys.readouterr()
        assert "invalid TOML" in captured.err

    def test_invalid_toml_falls_through_to_pyproject(self, temp_repo, capsys):
        (temp_repo / "xecurex.toml").write_text("not [ valid toml")
        (temp_repo / "pyproject.toml").write_text('[tool.xecurex]\nmin_severity = "medium"\n')
        config = load_config(temp_repo)
        assert config.min_severity == Severity.MEDIUM

    def test_confidence_threshold_loaded(self, temp_repo):
        (temp_repo / "xecurex.toml").write_text("[xecurex]\nconfidence_threshold = 0.9\n")
        config = load_config(temp_repo)
        assert config.confidence_threshold == 0.9


class TestIgnoreFile:
    def test_loads_xecurexignore(self, temp_repo):
        (temp_repo / ".xecurexignore").write_text(
            "# comment line\nfixtures\ntests/\n*.min.js\n\n/anchored\n",
            encoding="utf-8",
        )
        config = load_config(temp_repo)
        assert "fixtures" in config.exclude_dirs
        assert "tests" in config.exclude_dirs
        assert "*.min.js" in config.exclude_dirs
        assert "anchored" in config.exclude_dirs

    def test_ignore_patterns_are_applied(self, temp_repo):
        from xecurex.scanner import Scanner

        (temp_repo / ".xecurexignore").write_text("fixtures\n", encoding="utf-8")
        fixtures = temp_repo / "fixtures"
        fixtures.mkdir()
        (fixtures / "data.py").write_text('password = "secret123456"')
        (temp_repo / "app.py").write_text('password = "secret123456"')

        result = Scanner(load_config(temp_repo)).scan(temp_repo)
        files = {f.file for f in result.findings}
        assert "app.py" in files
        assert not any("fixtures" in f for f in files)

    def test_no_ignore_file_is_fine(self, temp_repo):
        config = load_config(temp_repo)
        assert "fixtures" not in config.exclude_dirs
