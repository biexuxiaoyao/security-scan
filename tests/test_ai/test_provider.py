"""Tests for security_scan.ai.provider."""

from __future__ import annotations

from security_scan.ai.provider import AIProvider


class TestAIProvider:
    def test_available_always_true(self):
        """available is always True — uses stdlib HTTP, no SDK needed."""
        provider = AIProvider({"ai": {"enabled": True}})
        assert provider.available is True

    def test_enabled_property(self):
        provider = AIProvider({"ai": {"enabled": True}})
        assert provider.enabled is True

    def test_disabled_by_default(self):
        provider = AIProvider({})
        assert provider.enabled is False

    def test_model_default(self):
        provider = AIProvider({"ai": {}})
        assert provider.model == "gpt-4o-mini"

    def test_model_custom(self):
        provider = AIProvider({"ai": {"model": "deepseek-chat"}})
        assert provider.model == "deepseek-chat"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("MY_CUSTOM_KEY", "sk-test123")
        provider = AIProvider({"ai": {"api_key_env": "MY_CUSTOM_KEY"}})
        assert provider.api_key == "sk-test123"
