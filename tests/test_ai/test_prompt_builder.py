"""Tests for security_scan.ai.prompt_builder."""

from __future__ import annotations

from security_scan.ai.prompt_builder import PromptBuilder


class TestPromptBuilder:
    def test_build_returns_messages(self):
        builder = PromptBuilder()
        finding = {
            "file_path": "src/App.java",
            "line_number": 42,
            "matched_content": 'password = "secret123"',
            "rule_id": "java_plaintext_password",
            "description": "Plaintext password detected",
        }
        messages = builder.build(finding)
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "src/App.java" in messages[1]["content"]

    def test_build_with_context(self):
        builder = PromptBuilder()
        finding = {
            "file_path": "a.java",
            "line_number": 3,
            "matched_content": "x",
            "rule_id": "r1",
            "description": "",
        }
        source = ["a", "b", "c", "d", "e"]
        messages = builder.build(finding, source)
        assert "3" in messages[1]["content"]

    def test_parse_response_valid_json(self):
        builder = PromptBuilder()
        result = builder.parse_response(
            '{"is_sensitive": true, "confidence": 0.95, "reason": "real secret"}'
        )
        assert result["is_sensitive"] is True
        assert result["confidence"] == 0.95

    def test_parse_response_false_positive(self):
        builder = PromptBuilder()
        result = builder.parse_response(
            '{"is_sensitive": false, "confidence": 0.85, "reason": "boolean default value"}'
        )
        assert result["is_sensitive"] is False

    def test_parse_response_invalid_fallback(self):
        builder = PromptBuilder()
        result = builder.parse_response("not json at all")
        assert result["is_sensitive"] is True  # fallback: treat as sensitive
        assert result["confidence"] == 0.5

    def test_parse_response_markdown_fence(self):
        builder = PromptBuilder()
        result = builder.parse_response(
            '```json\n{"is_sensitive": false, "confidence": 0.9, "reason": "test data"}\n```'
        )
        assert result["is_sensitive"] is False

    def test_build_batch(self):
        builder = PromptBuilder()
        findings = [
            {"file_path": "a.java", "line_number": 1, "matched_content": "x", "rule_id": "r1", "description": ""},
            {"file_path": "b.java", "line_number": 5, "matched_content": "y", "rule_id": "r2", "description": ""},
        ]
        prompts = builder.build_batch(findings)
        assert len(prompts) == 2
