"""Tests for security_scan.ai.provider — including HTTP mock for DeepSeek v4 Flash API."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from security_scan.ai.provider import AIProvider


class TestAIProviderProperties:
    def test_available_always_true(self):
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

    def test_api_key_from_config_fallback(self):
        provider = AIProvider({"ai": {"api_key": "config-key"}})
        assert provider.api_key == "config-key"

    def test_base_url_default(self):
        provider = AIProvider({"ai": {}})
        assert provider.base_url == "https://api.openai.com/v1"

    def test_base_url_custom(self):
        provider = AIProvider({"ai": {"base_url": "https://api.deepseek.com/v1"}})
        assert provider.base_url == "https://api.deepseek.com/v1"

    def test_timeout_default(self):
        provider = AIProvider({"ai": {}})
        assert provider.timeout == 10

    def test_max_retries_default(self):
        provider = AIProvider({"ai": {}})
        assert provider.max_retries == 3


class TestAIProviderClassify:
    """Mock HTTP layer to simulate DeepSeek v4 Flash API responses."""

    @patch("urllib.request.urlopen")
    def test_classify_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "id": "chatcmpl-xxx",
            "model": "deepseek-chat",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": '{"is_sensitive": true, "confidence": 0.95, "reason": "hardcoded password detected"}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130},
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        provider = AIProvider({"ai": {"enabled": True, "model": "deepseek-chat", "base_url": "https://api.deepseek.com/v1"}})
        messages = [{"role": "user", "content": "test prompt"}]
        result = provider.classify(messages)

        assert result["choices"][0]["message"]["content"] is not None
        assert result["model"] == "deepseek-chat"
        # Verify the request was sent to the right URL
        call_req = mock_urlopen.call_args[0][0]
        assert "api.deepseek.com" in call_req.host

    @patch("urllib.request.urlopen")
    def test_classify_encrypted_value_false_positive(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": '{"is_sensitive": false, "confidence": 0.90, "reason": "value starts with BEE_ encryption prefix"}'}}],
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        provider = AIProvider({"ai": {"enabled": True}})
        result = provider.classify([{"role": "user", "content": "test"}])
        content = result["choices"][0]["message"]["content"]
        assert "is_sensitive\": false" in content

    @patch("urllib.request.urlopen")
    def test_classify_sends_api_key(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        provider = AIProvider({"ai": {"enabled": True, "api_key": "sk-mykey"}})
        provider.classify([{"role": "user", "content": "hi"}])

        call_req = mock_urlopen.call_args[0][0]
        assert call_req.headers["Authorization"] == "Bearer sk-mykey"

    @patch("urllib.request.urlopen")
    def test_classify_without_api_key(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        provider = AIProvider({"ai": {"enabled": True}})
        provider.classify([{"role": "user", "content": "hi"}])

        call_req = mock_urlopen.call_args[0][0]
        assert "Authorization" not in call_req.headers

    @patch("urllib.request.urlopen")
    def test_classify_retries_on_failure(self, mock_urlopen):
        """Should retry up to max_retries times on URLError."""
        mock_urlopen.side_effect = OSError("Connection reset by peer")

        provider = AIProvider({"ai": {"enabled": True, "max_retries": 2}})
        import pytest
        with pytest.raises(RuntimeError, match="AI API call failed after 2 retries"):
            provider.classify([{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 2

    @patch("urllib.request.urlopen")
    def test_classify_retry_then_succeeds(self, mock_urlopen):
        """Retry twice then succeed on third attempt."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode("utf-8")

        mock_urlopen.side_effect = [
            OSError("Timeout"),
            OSError("Timeout"),
            MagicMock(__enter__=MagicMock(return_value=mock_resp)),
        ]

        provider = AIProvider({"ai": {"enabled": True, "max_retries": 3}})
        result = provider.classify([{"role": "user", "content": "test"}])
        assert result["choices"][0]["message"]["content"] == "ok"
        assert mock_urlopen.call_count == 3


class TestAIProviderClassifyBatch:
    def test_classify_batch_sequential(self):
        """classify_batch calls classify N times and returns N results."""
        provider = AIProvider({"ai": {"enabled": True}})

        with patch.object(provider, "classify") as mock_classify:
            mock_classify.return_value = {
                "choices": [{"message": {"content": '{"is_sensitive": false, "confidence": 0.8, "reason": "safe"}'}}]
            }
            prompts = [
                [{"role": "user", "content": "prompt1"}],
                [{"role": "user", "content": "prompt2"}],
            ]
            results = provider.classify_batch(prompts)

            assert len(results) == 2
            assert results[0]["is_sensitive"] is False
            assert mock_classify.call_count == 2

    def test_classify_batch_api_error_fallback(self):
        """When classify() raises, each item gets a fallback verdict."""
        provider = AIProvider({"ai": {"enabled": True}})

        with patch.object(provider, "classify") as mock_classify:
            mock_classify.side_effect = RuntimeError("API down")

            prompts = [[{"role": "user", "content": "p1"}]]
            results = provider.classify_batch(prompts)

            assert results[0]["is_sensitive"] is True  # fallback
            assert results[0]["confidence"] == 0.5
