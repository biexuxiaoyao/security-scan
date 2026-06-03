"""Tests for security_scan.scanner.classifier."""

from __future__ import annotations

from security_scan.scanner.classifier import FileClassifier


class TestFileClassifier:
    def test_java_is_ast(self):
        fc = FileClassifier({})
        assert fc.classify("App.java") == "ast"

    def test_yml_is_regex(self):
        fc = FileClassifier({})
        assert fc.classify("config.yml") == "regex"

    def test_unknown_extension_is_skip(self):
        fc = FileClassifier({})
        assert fc.classify("binary.exe") == "skip"

    def test_custom_format_from_config(self):
        config = {
            "file_formats": [
                {"extensions": [".conf", ".cfg"], "scan_strategy": "regex"}
            ]
        }
        fc = FileClassifier(config)
        assert fc.classify("server.conf") == "regex"
        assert fc.classify("server.cfg") == "regex"
        assert fc.classify("server.ini") == "skip"
