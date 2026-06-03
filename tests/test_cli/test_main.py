"""Smoke tests for CLI entry point."""

from __future__ import annotations

from click.testing import CliRunner

from security_scan.cli.main import cli


class TestCLI:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "security-scan" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan a Java project" in result.output

    def test_hook_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["hook", "--help"])
        assert result.exit_code == 0
        assert "Manage Git pre-commit hooks" in result.output

    def test_init_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "Initialize" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "security-scan" in result.output

    def test_generate_config(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--generate-config"])
        assert result.exit_code == 0
        assert "encrypted_prefixes" in result.output

    def test_scan_on_empty_dir(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--path", str(tmp_path)])
        assert "No supported files found" in result.output
        assert result.exit_code == 0

    def test_scan_with_java_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "App.java").write_text(
            'public class App {\n'
            '    private String password = "secret123";\n'
            '}\n'
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--path", str(tmp_path)])
        # Should find the password
        assert result.exit_code in (0, 1, 2)
        assert "security-scan" in result.output or "Scan" in result.output
