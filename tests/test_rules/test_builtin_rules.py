"""Tests for security_scan.rules.builtin_rules."""

from __future__ import annotations

from security_scan.rules.builtin_rules import get_rules_for_scope, match_rule_on_line


class TestGetRulesForScope:
    def test_all_scope_returns_all_rules(self):
        rules = get_rules_for_scope("all")
        assert len(rules) >= 6  # at least 6 all-scope built-in rules
        ids = {r["id"] for r in rules}
        assert "aws_access_key" in ids
        assert "private_key" in ids
        assert "jwt_token" in ids

    def test_config_scope_includes_credential_rule(self):
        rules = get_rules_for_scope("yaml")
        ids = {r["id"] for r in rules}
        assert "config_credential_key" in ids

    def test_java_scope_includes_java_rule(self):
        rules = get_rules_for_scope("java")
        ids = {r["id"] for r in rules}
        assert "java_plaintext_password" in ids


class TestMatchRuleOnLine:
    def test_match_aws_key(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "aws_access_key")
        result = match_rule_on_line(rule, 'aws_key = "AKIAIOSFODNN7EXAMPLE"', 1)
        assert result is not None
        assert result["rule_id"] == "aws_access_key"
        assert "AKIA" in result["matched_content"]

    def test_match_private_key(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "private_key")
        result = match_rule_on_line(
            rule, "-----BEGIN RSA PRIVATE KEY-----", 1
        )
        assert result is not None
        assert result["rule_id"] == "private_key"

    def test_no_match_on_clean_line(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "aws_access_key")
        result = match_rule_on_line(rule, "x = 42", 1)
        assert result is None

    def test_match_config_password(self):
        rule = next(
            r for r in get_rules_for_scope("config") if r["id"] == "config_credential_key"
        )
        result = match_rule_on_line(rule, "password: supersecret", 5)
        assert result is not None
        assert result["line_number"] == 5
        assert result["severity"] == "HIGH"

    def test_match_default_password(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "default_password")
        result = match_rule_on_line(rule, 'password = "admin"', 3)
        assert result is not None
        assert result["rule_id"] == "default_password"
        assert result["severity"] == "MEDIUM"
