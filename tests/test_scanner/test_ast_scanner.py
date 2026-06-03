"""Tests for security_scan.scanner.ast_scanner — tree-sitter Java AST analysis."""

from __future__ import annotations

from pathlib import Path

from security_scan.rules import RuleEngine
from security_scan.scanner.ast_scanner import (
    ASTScanner,
    _extract_default_from_el,
    _is_plausible_secret,
)


class TestSpELParsing:
    """_extract_default_from_el tests."""

    def test_extract_password_default(self):
        assert _extract_default_from_el("${db.password:password123}") == "password123"

    def test_extract_boolean_default(self):
        assert _extract_default_from_el("${feature.enabled:true}") == "true"

    def test_extract_numeric_default(self):
        assert _extract_default_from_el("${max.retry:3}") == "3"

    def test_extract_version_default(self):
        assert _extract_default_from_el("${app.version:1.2.3}") == "1.2.3"

    def test_no_default(self):
        assert _extract_default_from_el("${api.base-url}") is None

    def test_not_spel(self):
        assert _extract_default_from_el("hardcoded") is None

    def test_encrypted_prefix_in_default(self):
        val = _extract_default_from_el("${redis.password:BEE_7x9k2m4n8q}")
        assert val == "BEE_7x9k2m4n8q"


class TestPlausibleSecret:
    def test_long_string(self):
        assert _is_plausible_secret("sk-abcdefghijklmnopqrstuvwxyz") is True

    def test_short_string(self):
        assert _is_plausible_secret("abc") is False

    def test_known_weak(self):
        assert _is_plausible_secret("password") is True
        assert _is_plausible_secret("admin") is True

    def test_clean_text(self):
        assert _is_plausible_secret("hello world") is False


class TestASTScannerIntegration:
    """Integration tests with real Java source via tree-sitter."""

    def make_scanner(self) -> ASTScanner:
        config = {"encrypted_prefixes": ["BEE_", "ENC(", "{cipher}", "$2a$"]}
        return ASTScanner(config)

    def make_engine(self) -> RuleEngine:
        return RuleEngine({
            "encrypted_prefixes": ["BEE_", "ENC(", "{cipher}", "$2a$"],
            "severity": {"min_confidence_to_report": 0.0},
        })

    def test_safe_config_no_findings(self, fixture_dir: Path):
        """SafeConfig.java should produce no critical findings."""
        scanner = self.make_scanner()
        engine = self.make_engine()
        java_file = fixture_dir / "java-samples" / "SafeConfig.java"
        findings = scanner.scan(str(java_file), engine)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0, f"Expected 0 critical, got: {critical}"

    def test_unsafe_config_finds_password(self, fixture_dir: Path):
        """UnsafeConfig.java should flag password."""
        scanner = self.make_scanner()
        engine = self.make_engine()
        java_file = fixture_dir / "java-samples" / "UnsafeConfig.java"
        findings = scanner.scan(str(java_file), engine)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) >= 1
        contents = " ".join(f.get("matched_content", "") for f in critical)
        assert "password123" in contents or "sk-" in contents

    def test_encrypted_config_no_critical(self, fixture_dir: Path):
        """EncryptedConfig.java should not produce critical findings."""
        scanner = self.make_scanner()
        engine = self.make_engine()
        java_file = fixture_dir / "java-samples" / "EncryptedConfig.java"
        findings = scanner.scan(str(java_file), engine)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0, f"Expected 0 critical, got: {critical}"
        encrypted = [f for f in findings if f.get("encrypted")]
        assert len(encrypted) >= 1

    def test_value_annotation_boolean_demoted(self, tmp_path: Path):
        """@Value with boolean default should demote severity."""
        java = tmp_path / "TestBool.java"
        java.write_text("""
public class TestBool {
    @Value("${feature.enabled:true}")
    private boolean featureEnabled;
}
""")
        scanner = self.make_scanner()
        engine = self.make_engine()
        findings = scanner.scan(str(java), engine)
        high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        assert len(high) == 0

    def test_value_annotation_password_critical(self, tmp_path: Path):
        """@Value with password default should produce CRITICAL."""
        java = tmp_path / "TestPassword.java"
        java.write_text("""
public class TestPassword {
    @Value("${db.password:password123}")
    private String dbPassword;
}
""")
        scanner = self.make_scanner()
        engine = self.make_engine()
        findings = scanner.scan(str(java), engine)
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) >= 1
        assert "password123" in critical[0].get("matched_content", "")

    def test_encrypted_value_in_annotation_demoted(self, tmp_path: Path):
        """@Value with BEE_ encrypted prefix should not be critical."""
        java = tmp_path / "TestEncryptedAnnotation.java"
        java.write_text("""
public class TestEncryptedAnnotation {
    @Value("${redis.password:BEE_7x9k2m4n8q}")
    private String redisPassword;
}
""")
        scanner = self.make_scanner()
        engine = self.make_engine()
        findings = scanner.scan(str(java), engine)
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0
        encrypted = [f for f in findings if f.get("encrypted")]
        assert len(encrypted) >= 1

    def test_direct_assignment_detected(self, tmp_path: Path):
        """private String x = "secret" should be detected."""
        java = tmp_path / "TestDirect.java"
        java.write_text("""
public class TestDirect {
    private String secretKey = "sk-abcdefghijklmnopqrstuvwxyz";
}
""")
        scanner = self.make_scanner()
        engine = self.make_engine()
        findings = scanner.scan(str(java), engine)
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) >= 1

    def test_fallback_to_regex_when_tree_sitter_fails(self, tmp_path: Path, monkeypatch):
        """When tree-sitter is unavailable, fall back to regex scanning."""
        monkeypatch.setattr(
            "security_scan.scanner.ast_scanner._TREE_SITTER_AVAILABLE",
            False,
        )
        java = tmp_path / "Fallback.java"
        java.write_text('public class F {\n    private String secret = "secret123";\n}\n')
        scanner = self.make_scanner()
        engine = self.make_engine()
        findings = scanner.scan(str(java), engine)
        assert len(findings) >= 1

    def test_binary_file_skipped(self, tmp_path: Path):
        """Binary files should be skipped."""
        f = tmp_path / "Test.class"
        f.write_bytes(b"\x00\x01\x02\x03")
        scanner = self.make_scanner()
        engine = self.make_engine()
        assert scanner.scan(str(f), engine) == []
