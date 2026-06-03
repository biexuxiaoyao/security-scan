"""Tests for inline ignore in RuleEngine."""

from __future__ import annotations

from security_scan.rules import RuleEngine


class TestInlineIgnore:
    def test_inline_ignore_suppresses_finding(self):
        engine = RuleEngine({
            "encrypted_prefixes": [],
            "severity": {"min_confidence_to_report": 0.0},
        })
        findings = engine.scan_line(
            'password = "secret123"  // security-scan:ignore',
            1, "properties",
        )
        assert findings == []

    def test_without_ignore_normal_scan(self):
        engine = RuleEngine({
            "encrypted_prefixes": [],
            "severity": {"min_confidence_to_report": 0.0},
        })
        findings = engine.scan_line(
            'password = "secret123"',
            1, "properties",
        )
        assert len(findings) >= 1
