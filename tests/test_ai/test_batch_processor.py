"""Tests for security_scan.ai.batch_processor — mock provider for DeepSeek v4 Flash integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from security_scan.ai.batch_processor import BatchProcessor


class TestBatchProcessorDisabled:
    def test_returns_findings_when_ai_disabled(self):
        bp = BatchProcessor({"ai": {"enabled": False}})
        findings = [{"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}]
        result = bp.process(findings)
        assert len(result) == 1
        assert result[0]["ai_reason"] is not None
        assert "unavailable" in result[0]["ai_reason"]

    def test_returns_findings_when_provider_unavailable(self):
        bp = BatchProcessor({"ai": {"enabled": True}})
        # provider.available is always True now, so we can't test "unavailable"
        # via the normal path. Instead we test the fallback directly.
        findings = [{"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}]
        result = bp._noop_fallback(findings)
        assert result[0]["ai_verdict"] is True
        assert result[0]["ai_confidence"] == 0.0
        assert result[0]["ai_dismissed"] is False
        assert "unavailable" in result[0]["ai_reason"]


class TestBatchProcessorMergeVerdict:
    def test_merge_ai_confirms_high_confidence(self):
        bp = BatchProcessor({"ai": {"confidence_threshold": 0.7}})
        finding = {"severity": "HIGH", "confidence": 0.5, "rule_id": "r1", "file_path": "a.java", "line_number": 1}
        verdict = {"is_sensitive": True, "confidence": 0.95, "reason": "real password"}
        bp._merge_verdict(finding, verdict)

        assert finding["ai_verdict"] is True
        assert finding.get("ai_dismissed") is not True
        # confidence should be boosted above threshold
        assert finding["confidence"] >= 0.9

    def test_merge_ai_dismisses_false_positive(self):
        bp = BatchProcessor({"ai": {"confidence_threshold": 0.7}})
        finding = {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}
        verdict = {"is_sensitive": False, "confidence": 0.85, "reason": "boolean default"}
        bp._merge_verdict(finding, verdict)

        assert finding["ai_verdict"] is False
        assert finding["ai_dismissed"] is True
        # severity should be demoted
        assert finding["severity"] == "LOW"
        # confidence should be lowered
        assert finding["confidence"] <= 0.1

    def test_merge_low_ai_confidence_does_not_override(self):
        bp = BatchProcessor({"ai": {"confidence_threshold": 0.7}})
        finding = {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}
        verdict = {"is_sensitive": True, "confidence": 0.5, "reason": "unsure"}
        bp._merge_verdict(finding, verdict)

        # AI fields set, but original severity/confidence kept
        assert finding["ai_verdict"] is True
        assert finding.get("ai_dismissed") is None
        assert finding["severity"] == "HIGH"
        assert finding["confidence"] == 0.8


class TestBatchProcessorIntegration:
    def test_process_calls_provider_and_merges(self):
        bp = BatchProcessor({"ai": {"enabled": True, "confidence_threshold": 0.7}})
        findings = [
            {"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1},
            {"severity": "MEDIUM", "confidence": 0.5, "rule_id": "r2", "file_path": "b.java", "line_number": 5},
        ]

        with patch.object(bp.provider, "classify_batch") as mock_classify_batch:
            mock_classify_batch.return_value = [
                {"is_sensitive": False, "confidence": 0.9, "reason": "test data in test file"},
                {"is_sensitive": True, "confidence": 0.85, "reason": "hardcoded key"},
            ]
            result = bp.process(findings)

            assert len(result) == 2
            # First finding dismissed
            assert result[0]["ai_dismissed"] is True
            assert result[0]["severity"] == "LOW"
            # Second finding confirmed
            assert result[1].get("ai_confirmed") is True
            assert result[1]["confidence"] >= 0.9

    def test_process_batches_large_finding_list(self):
        bp = BatchProcessor({"ai": {"enabled": True, "batch_size": 2}})
        findings = [
            {"rule_id": f"r{i}", "file_path": "a.java", "line_number": i, "severity": "HIGH", "confidence": 0.8}
            for i in range(5)
        ]

        with patch.object(bp.provider, "classify_batch") as mock_classify_batch:
            mock_classify_batch.return_value = [
                {"is_sensitive": False, "confidence": 0.9, "reason": "safe"} for _ in range(5)
            ]
            result = bp.process(findings)
            assert len(result) == 5
            # Should be called 3 times (2+2+1 for batch_size=2)
            assert mock_classify_batch.call_count == 3

    def test_process_with_context_lines(self):
        bp = BatchProcessor({"ai": {"enabled": True}})
        findings = [{"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 3}]
        source_map = {"a.java": ["line1", "line2", "line3", "line4", "line5"]}

        with patch.object(bp.provider, "classify_batch") as mock_classify_batch:
            mock_classify_batch.return_value = [{"is_sensitive": True, "confidence": 0.5, "reason": "unsure"}]
            bp.process(findings, source_map)

            # Verify prompt was built with context
            prompts_arg = mock_classify_batch.call_args[0][0]
            assert len(prompts_arg) == 1
            assert "line2" in prompts_arg[0][1]["content"]
            assert "line4" in prompts_arg[0][1]["content"]


class TestBatchProcessorDemote:
    def test_demote_severity(self):
        bp = BatchProcessor({})
        assert bp._demote("CRITICAL", 1) == "HIGH"
        assert bp._demote("CRITICAL", 3) == "LOW"
        assert bp._demote("HIGH", 2) == "LOW"
        assert bp._demote("LOW", 1) == "LOW"

    def test_demote_unknown_severity(self):
        bp = BatchProcessor({})
        assert bp._demote("UNKNOWN", 1) == "UNKNOWN"
