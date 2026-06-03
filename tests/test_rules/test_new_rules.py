"""Tests for newly added rules: password_in_comment, sensitive_log."""

from __future__ import annotations

from security_scan.rules.builtin_rules import get_rules_for_scope, match_rule_on_line


class TestPasswordInComment:
    def test_comment_with_password(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "password_in_comment")
        result = match_rule_on_line(rule, "// password is admin123", 1)
        assert result is not None
        assert result["rule_id"] == "password_in_comment"

    def test_properties_comment(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "password_in_comment")
        result = match_rule_on_line(rule, "# password = root", 1)
        assert result is not None

    def test_xml_comment(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "password_in_comment")
        result = match_rule_on_line(rule, "<!-- password = sekret -->", 1)
        assert result is not None

    def test_clean_comment(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "password_in_comment")
        result = match_rule_on_line(rule, "// normal comment about login", 1)
        assert result is None


class TestSensitiveLog:
    def test_log_with_password(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "sensitive_log")
        result = match_rule_on_line(
            rule, 'logger.info("password: {}", userPassword)', 5
        )
        assert result is not None
        assert result["rule_id"] == "sensitive_log"

    def test_log_with_secret(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "sensitive_log")
        result = match_rule_on_line(
            rule, 'log.debug("secret value: {}", secret)', 3
        )
        assert result is not None

    def test_clean_log(self):
        rule = next(r for r in get_rules_for_scope("all") if r["id"] == "sensitive_log")
        result = match_rule_on_line(
            rule, 'logger.info("user login: {}", username)', 1
        )
        assert result is None
