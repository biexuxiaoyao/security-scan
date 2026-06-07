"""Tests for security_scan.utils.encryption."""

from __future__ import annotations

from security_scan.utils.encryption import check_encrypted_prefix, extract_value_from_content


class TestCheckEncryptedPrefix:
    def test_matches_first_prefix(self):
        assert check_encrypted_prefix("BEE_abc123", ["BEE_", "ENC("]) == (True, "BEE_")

    def test_matches_second_prefix(self):
        assert check_encrypted_prefix("ENC(xyz)", ["BEE_", "ENC("]) == (True, "ENC(")

    def test_no_match(self):
        assert check_encrypted_prefix("plaintext", ["BEE_", "ENC("]) == (False, None)

    def test_empty_prefix_list(self):
        assert check_encrypted_prefix("BEE_abc", []) == (False, None)

    def test_empty_value(self):
        assert check_encrypted_prefix("", ["BEE_"]) == (False, None)

    def test_prefix_at_start(self):
        assert check_encrypted_prefix("  BEE_abc", ["BEE_"]) == (True, "BEE_")


class TestExtractValueFromContent:
    def test_equals_separator(self):
        assert extract_value_from_content("password=secret123") == "secret123"

    def test_colon_separator(self):
        assert extract_value_from_content("password: secret123") == "secret123"

    def test_equals_preferred_over_colon(self):
        assert extract_value_from_content("url=https://example.com:8080") == "https://example.com:8080"

    def test_no_separator(self):
        assert extract_value_from_content("justtext") == "justtext"

    def test_quotes_stripped(self):
        assert extract_value_from_content('password="secret123"') == "secret123"
