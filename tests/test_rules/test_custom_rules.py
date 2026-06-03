"""Tests for security_scan.rules.custom_rules."""

from __future__ import annotations

from security_scan.rules.custom_rules import CustomRuleLoader


class TestCustomRuleLoader:
    def test_empty_config_returns_empty(self):
        loader = CustomRuleLoader({})
        assert loader.load() == []

    def test_invalid_config_type_returns_empty(self):
        loader = CustomRuleLoader({"custom_rules": "not_a_list"})
        assert loader.load() == []

    def test_valid_rule_is_loaded(self):
        config = {
            "custom_rules": [
                {
                    "id": "my_rule",
                    "name": "My Rule",
                    "pattern": r"secret\s*=\s*(.+)",
                    "severity": "CRITICAL",
                }
            ]
        }
        loader = CustomRuleLoader(config)
        rules = loader.load()
        assert len(rules) == 1
        assert rules[0]["id"] == "my_rule"
        assert rules[0]["pattern"].search('secret = "hello"')

    def test_missing_required_keys_skipped(self):
        config = {
            "custom_rules": [
                {"id": "no_pattern"},  # missing pattern, severity
                {
                    "id": "good",
                    "name": "Good",
                    "pattern": r"test",
                    "severity": "LOW",
                },
            ]
        }
        loader = CustomRuleLoader(config)
        rules = loader.load()
        assert len(rules) == 1
        assert rules[0]["id"] == "good"

    def test_invalid_regex_is_skipped(self):
        config = {
            "custom_rules": [
                {
                    "id": "bad_regex",
                    "name": "Bad",
                    "pattern": r"[invalid",
                    "severity": "HIGH",
                }
            ]
        }
        loader = CustomRuleLoader(config)
        assert loader.load() == []
