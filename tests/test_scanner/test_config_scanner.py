"""Tests for security_scan.scanner.config_scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_scan.scanner.config_scanner import (
    ConfigKeyValueScanner,
    _is_excluded,
    _try_parse_key_value,
    _is_asterisk_masked,
    _matches_any,
)
from security_scan.utils.encryption import check_encrypted_prefix


# ── test helpers ───────────────────────────────────────────────

_DEFAULT_CONFIG = {
    "config_file_secrets": {
        "enabled": True,
        "exclude_patterns": ["messages_*.properties"],
        "key_rules": [
            {
                "id": "config_plaintext_password",
                "name": "配置文件明文密码",
                "severity": "HIGH",
                "patterns": [
                    "(?i).*redis.*(?:password|auth|pass|secret)$",
                    "(?i)ZOO_SERVER_PASSWORDS|ZOO\\.SERVER\\.PASSWORDS",
                ],
            },
            {
                "id": "config_plaintext_key",
                "name": "配置文件明文密钥",
                "severity": "HIGH",
                "patterns": [
                    "(?i).*(?:password|secret|pwd|key|token)$",
                ],
            },
            {
                "id": "config_plaintext_token",
                "name": "配置文件明文Token",
                "severity": "HIGH",
                "patterns": [
                    "(?i)sasl\\.jaas\\.config",
                    "(?i)spring\\.kafka\\.properties\\.sasl\\.jaas\\.config",
                    "(?i)spring\\.kafka\\.producer\\.properties\\.sasl\\.jaas\\.config",
                    "(?i)spring\\.kafka\\.consumer\\.properties\\.sasl\\.jaas\\.config",
                    "(?i)bee\\.kafka\\.ds1\\.properties\\.sasl\\.jaas\\.config",
                    "(?i)bee\\.kafka\\.ds2\\.properties\\.sasl\\.jaas\\.config",
                ],
            },
        ],
        "key_whitelist": [
            "(?i)^(?:publicKey|public.key|public-key|pubKey|public_key|appKey|access.key|access-key|accesskey)$",
            "(?i)^(?:topickey|relatedkey|related-key|binding-routing-key)$",
            "(?i).*RelatedKey.*",
            "(?i).*poseidon.*",
            "(?i)^(?:ignoretoken|bee\\.microservice\\.token)$",
        ],
        "value_encrypted_prefixes": [
            "BEE_", "ENC(", "{ciph",
            "encrypt:", "M_ENC",
            "LSFI_ENV_COMMON",
        ],
        "value_placeholder_patterns": [
            "^\\$\\([^)]+\\)$",
            "^\\$\\{[^}]+\\}$",
            "^<[^>]+>$",
            "^@[^@]+@$",
        ],
    }
}


# ── unit: helper functions ────────────────────────────────────


class TestIsExcluded:
    def test_messages_properties_excluded(self):
        assert _is_excluded("messages_zh_CN.properties", ["messages_*.properties"]) is True
        assert _is_excluded("messages_en.properties", ["messages_*.properties"]) is True
        assert _is_excluded("application.properties", ["messages_*.properties"]) is False

    def test_no_exclude_patterns(self):
        assert _is_excluded("any.properties", []) is False


class TestTryParseKeyValue:
    def test_properties_format(self):
        assert _try_parse_key_value("redis.password=secret123") == ("redis.password", "secret123")

    def test_yaml_format(self):
        assert _try_parse_key_value("redis.password: secret123") == ("redis.password", "secret123")

    def test_quoted_value(self):
        assert _try_parse_key_value('password="secret123"') == ("password", "secret123")

    def test_comment_line_returns_none(self):
        assert _try_parse_key_value("# this is a comment") is None
        assert _try_parse_key_value("!comment") is None

    def test_blank_line_returns_none(self):
        assert _try_parse_key_value("") is None
        assert _try_parse_key_value("   ") is None

    def test_no_separator_returns_none(self):
        assert _try_parse_key_value("just a string") is None

    def test_colon_in_value(self):
        result = _try_parse_key_value("url: https://example.com:8080")
        assert result is not None
        assert result[0] == "url"
        assert "https://example.com:8080" in result[1]


class TestIsAsteriskMasked:
    def test_all_asterisks(self):
        assert _is_asterisk_masked("****") is True
        assert _is_asterisk_masked("*") is True

    def test_not_asterisks(self):
        assert _is_asterisk_masked("secret") is False
        assert _is_asterisk_masked("**a*") is False

    def test_empty_string(self):
        assert _is_asterisk_masked("") is False


class TestMatchesAny:
    def test_matches(self):
        patterns = [__import__("re").compile(p) for p in [r"^\$\{[^}]+\}$"]]
        assert _matches_any("${db.password}", patterns) is True

    def test_no_match(self):
        patterns = [__import__("re").compile(p) for p in [r"^\$\{[^}]+\}$"]]
        assert _matches_any("secret123", patterns) is False


class TestCheckEncryptedPrefix:
    def test_matches(self):
        assert check_encrypted_prefix("BEE_abc123", ["BEE_"]) == (True, "BEE_")
        assert check_encrypted_prefix("ENC(xyz)", ["ENC("]) == (True, "ENC(")

    def test_no_match(self):
        assert check_encrypted_prefix("secret123", ["BEE_", "ENC("]) == (False, None)


# ── integration: full scanner ─────────────────────────────────


class TestConfigKeyValueScanner:
    def _make_scanner(self, overrides: dict | None = None) -> ConfigKeyValueScanner:
        import copy
        config = copy.deepcopy(_DEFAULT_CONFIG)
        if overrides:
            config["config_file_secrets"].update(overrides)
        return ConfigKeyValueScanner(config)

    def test_disabled_returns_empty(self):
        scanner = self._make_scanner({"enabled": False})
        result = scanner.scan("any.properties")
        assert result == []

    def test_messages_properties_excluded(self):
        scanner = self._make_scanner()
        result = scanner.scan("messages_zh_CN.properties")
        assert result == []

    # ── key matching ──────────────────────────────────────────

    def test_redis_password_found(self, tmp_path):
        f = tmp_path / "redis.yml"
        f.write_text("redis.password: plaintext123\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_password"
        assert result[0]["severity"] == "HIGH"

    def test_redis_auth_found(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("spring.redis.auth=secret456\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_password"

    def test_zookeeper_password_found(self, tmp_path):
        f = tmp_path / "zk.properties"
        f.write_text("ZOO_SERVER_PASSWORDS=p@ssw0rd\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_password"

    def test_generic_password_found(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("myapp.password=secret123\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_key"

    def test_generic_secret_found(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("db.secret=supersecret\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_key"

    def test_generic_token_found(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("auth.token=eyJhbGciOiJIUzI1NiJ9\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_key"

    def test_kafka_jaas_found(self, tmp_path):
        f = tmp_path / "kafka.yml"
        f.write_text("sasl.jaas.config: org.apache.kafka.common.security.plain.PlainLoginModule\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_token"

    def test_bee_kafka_ds1_jaas_found(self, tmp_path):
        f = tmp_path / "kafka.properties"
        f.write_text("bee.kafka.ds1.properties.sasl.jaas.config=secret\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["rule_id"] == "config_plaintext_token"

    # ── key whitelist ─────────────────────────────────────────

    @pytest.mark.parametrize("key", [
        "publicKey", "public.key", "public-key", "pubKey",
        "public_key", "appKey", "access.key", "access-key", "accesskey",
    ])
    def test_public_key_whitelisted(self, tmp_path, key):
        f = tmp_path / "app.properties"
        f.write_text(f"{key}=somevalue\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], f"{key} should be whitelisted"

    @pytest.mark.parametrize("key", [
        "topickey", "relatedkey", "related-key", "binding-routing-key",
    ])
    def test_topic_key_whitelisted(self, tmp_path, key):
        f = tmp_path / "app.properties"
        f.write_text(f"{key}=somevalue\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], f"{key} should be whitelisted"

    def test_related_key_whitelisted(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("my.RelatedKey.topic=value\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], "RelatedKey should be whitelisted"

    def test_poseidon_whitelisted(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("poseidon.secret.key=value\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], "poseidon should be whitelisted"

    def test_ignoretoken_whitelisted(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("ignoretoken=abc\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], "ignoretoken should be whitelisted"

    def test_bee_microservice_token_whitelisted(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("bee.microservice.token=abc123\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == [], "bee.microservice.token should be whitelisted"

    # ── value encrypted ───────────────────────────────────────

    @pytest.mark.parametrize("prefix,value", [
        ("BEE_", "BEE_abc123def456"),
        ("ENC(", "ENC(abc123)"),
        ("{ciph", "{cipher}abc123"),
        ("encrypt:", "encrypt:abc123"),
        ("M_ENC", "M_ENCabc123"),
        ("LSFI_ENV_COMMON", "LSFI_ENV_COMMON_MzliZjVkZjlmMjU4MBuSW6p"),
    ])
    def test_encrypted_value_downgraded(self, tmp_path, prefix, value):
        f = tmp_path / "app.properties"
        f.write_text(f"db.password={value}\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["encrypted"] is True
        assert result[0]["severity"] == "LOW"
        assert result[0]["confidence"] == 0.0

    # ── value asterisk masked ─────────────────────────────────

    def test_asterisk_masked_value_downgraded(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("db.password=****\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0].get("_safe_placeholder") is True
        assert result[0]["severity"] == "LOW"
        assert result[0]["confidence"] == 0.1

    # ── value placeholder ─────────────────────────────────────

    @pytest.mark.parametrize("value", [
        "$(db.password)", "${db.password}",
        "<db.password>", "@acs-v1.datasource.password@",
    ])
    def test_placeholder_value_downgraded(self, tmp_path, value):
        f = tmp_path / "app.properties"
        f.write_text(f"db.password={value}\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0].get("_safe_placeholder") is True
        assert result[0]["severity"] == "LOW"

    # ── non-sensitive key ─────────────────────────────────────

    def test_non_sensitive_key_no_finding(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("server.port=8080\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == []

    def test_key_ending_without_suffix_no_finding(self, tmp_path):
        f = tmp_path / "app.properties"
        f.write_text("server.name=myserver\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == []

    # ── edge cases ────────────────────────────────────────────

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.properties"
        f.write_text("")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == []

    def test_multiple_findings_in_one_file(self, tmp_path):
        f = tmp_path / "multi.properties"
        f.write_text(
            "redis.password=secret1\n"
            "db.secret=secret2\n"
            "server.name=ok\n"
        )
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 2  # redis.password + db.secret, not server.name

    def test_yml_format(self, tmp_path):
        f = tmp_path / "config.yml"
        f.write_text("redis:\n  password: plaintext\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["config_key"] == "redis.password"

    def test_nested_yaml_detects_redis_password(self, tmp_path):
        """YAML nesting: ``spring.redis.password`` must match ``redis.*password``."""
        f = tmp_path / "app.yml"
        f.write_text(
            "spring:\n"
            "  redis:\n"
            "    host: localhost\n"
            "    password: secret123\n"
        )
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["config_key"] == "spring.redis.password"
        assert result[0]["rule_id"] == "config_plaintext_password"

    def test_yaml_parse_failure_falls_back_empty(self, tmp_path):
        """Malformed YAML should not raise, just return empty."""
        f = tmp_path / "bad.yml"
        f.write_text(": invalid yaml :: \n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert result == []

    def test_yaml_encrypted_value_detected_via_nested_path(self, tmp_path):
        """Encrypted prefix on nested YAML key is detected."""
        f = tmp_path / "app.yml"
        f.write_text("spring:\n  redis:\n    password: BEE_encrypted_value\n")
        scanner = self._make_scanner()
        result = scanner.scan(str(f))
        assert len(result) == 1
        assert result[0]["encrypted"] is True
        assert result[0]["severity"] == "LOW"
