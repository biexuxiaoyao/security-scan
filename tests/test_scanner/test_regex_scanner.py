"""Tests for security_scan.scanner.regex_scanner."""

from __future__ import annotations

from pathlib import Path

from security_scan.rules import RuleEngine
from security_scan.scanner.regex_scanner import RegexScanner, _scope_from_suffix


class TestScopeFromSuffix:
    def test_java_scope(self):
        assert _scope_from_suffix(".java") == "java"

    def test_yaml_scope(self):
        assert _scope_from_suffix(".yml") == "yaml"

    def test_unknown_scope(self):
        assert _scope_from_suffix(".exe") == "all"


class TestRegexScanner:
    def test_scan_finds_password_in_yaml(self, tmp_path: Path):
        config_file = tmp_path / "app.yml"
        config_file.write_text("password: supersecret\nhost: localhost\n")

        config = {"encrypted_prefixes": [], "severity": {"min_confidence_to_report": 0.0}}
        engine = RuleEngine(config)
        scanner = RegexScanner(engine)
        findings = scanner.scan(str(config_file))

        assert len(findings) >= 1
        assert any("supersecret" in f.get("matched_content", "") for f in findings)

    def test_scan_encrypted_value_suppressed(self, tmp_path: Path):
        config_file = tmp_path / "app.yml"
        config_file.write_text('password: "BEE_abc123xyz=="\n')

        config = {"encrypted_prefixes": ["BEE_"], "severity": {"min_confidence_to_report": 0.0}}
        engine = RuleEngine(config)
        scanner = RegexScanner(engine)
        findings = scanner.scan(str(config_file))

        # Should be found but marked as encrypted
        encrypted = [f for f in findings if f.get("encrypted")]
        assert len(encrypted) >= 1

    def test_scan_non_existent_file(self):
        config = {"encrypted_prefixes": [], "severity": {"min_confidence_to_report": 0.0}}
        engine = RuleEngine(config)
        scanner = RegexScanner(engine)
        findings = scanner.scan("/tmp/nonexistent_file_12345.yml")
        assert findings == []

    def test_scan_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.properties"
        f.write_text("")
        config = {"encrypted_prefixes": [], "severity": {"min_confidence_to_report": 0.0}}
        engine = RuleEngine(config)
        scanner = RegexScanner(engine)
        findings = scanner.scan(str(f))
        assert findings == []
