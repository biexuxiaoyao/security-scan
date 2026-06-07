"""Tests for security_scan.ai.classifier — top-level AI classification API."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from security_scan.ai.classifier import AIClassifier


class TestAIClassifier:
    def test_classify_with_ai_enabled(self):
        classifier = AIClassifier({"ai": {"enabled": True}})
        findings = [
            {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}
        ]

        with patch.object(classifier.batch_processor, "process") as mock_process:
            mock_process.return_value = findings
            result = classifier.classify(findings)
            assert len(result) == 1

    def test_classify_with_ai_disabled(self):
        classifier = AIClassifier({"ai": {"enabled": False}})
        findings = [
            {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}
        ]
        result = classifier.classify(findings)
        # Returns findings with fallback AI fields
        assert result[0].get("ai_verdict") is True
        assert "unavailable" in result[0].get("ai_reason", "")

    def test_available_property(self):
        classifier = AIClassifier({"ai": {"enabled": True}})
        # provider.available is always True (stdlib HTTP)
        assert classifier.available is True

    def test_available_when_disabled(self):
        classifier = AIClassifier({"ai": {"enabled": False}})
        # available checks both enabled and provider.available
        assert classifier.available is False

    def test_classify_with_context_map(self):
        classifier = AIClassifier({"ai": {"enabled": True}})
        findings = [
            {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "test.java", "line_number": 1}
        ]
        source_map = {"test.java": ["line1", "line2"]}

        with patch.object(classifier.batch_processor, "process") as mock_process:
            mock_process.return_value = findings
            classifier.classify(findings, source_map)
            # Verify context was passed through
            args, _kwargs = mock_process.call_args
            assert args[0] == findings
            assert args[1] == source_map

    def test_read_source_lines(self, tmp_path):
        classifier = AIClassifier({"ai": {"enabled": True}})
        f1 = tmp_path / "a.java"
        f1.write_text("line1\nline2\nline3\n")
        f2 = tmp_path / "b.java"
        f2.write_text("hello\n")

        result = classifier.read_source_lines([str(f1), str(f2)])
        assert str(f1) in result
        assert str(f2) in result
        assert result[str(f1)] == ["line1", "line2", "line3"]

    def test_read_source_lines_skips_missing(self):
        classifier = AIClassifier({"ai": {"enabled": True}})
        result = classifier.read_source_lines(["/nonexistent/file.java"])
        assert result == {}
