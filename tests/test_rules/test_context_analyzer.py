"""Tests for security_scan.rules.context_analyzer."""

from __future__ import annotations

from security_scan.rules.context_analyzer import ContextAnalyzer


class TestContextAnalyzer:
    def make_finding(self, content: str, rule_id: str = "config_credential_key",
                     severity: str = "HIGH") -> dict:
        return {
            "matched_content": content,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": 0.85,
        }

    def test_boolean_value_confidence_demoted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('enabled: true')
        ca.analyze(f)
        assert f["confidence"] <= 0.20

    def test_numeric_value_confidence_demoted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('port: 8080')
        ca.analyze(f)
        assert f["confidence"] <= 0.15

    def test_version_string_confidence_demoted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('version: 1.2.3')
        ca.analyze(f)
        assert f["confidence"] <= 0.10

    def test_url_value_demoted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('url: https://example.com')
        ca.analyze(f)
        assert f["confidence"] <= 0.15

    def test_key_name_hint_demoted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('enabled: true')
        ca.analyze(f)
        assert f["severity"] != "HIGH"  # should be demoted

    def test_long_password_value_boosted(self):
        ca = ContextAnalyzer({})
        f = self.make_finding(
            'password: mysecretpassword123',
            rule_id="java_plaintext_password",
        )
        ca.analyze(f)
        assert f["confidence"] >= 0.90

    def test_encrypted_finding_unchanged(self):
        ca = ContextAnalyzer({})
        f = self.make_finding('password: BEE_abc123')
        f["encrypted"] = True
        f["confidence"] = 0.0
        ca.analyze(f)
        assert f["confidence"] == 0.0
