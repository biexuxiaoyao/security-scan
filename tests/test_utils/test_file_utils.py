"""Tests for security_scan.utils.file_utils."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_scan.utils.file_utils import (
    is_binary_file,
    is_supported_extension,
    normalize_path,
    read_file_safe,
)


class TestReadFileSafe:
    """read_file_safe tests."""

    def test_utf8_file(self, tmp_path: Path):
        f = tmp_path / "hello.java"
        f.write_text('class A {}\n', encoding="utf-8")
        content, enc, conf = read_file_safe(f)
        assert "class A" in content
        assert enc == "utf-8"
        assert conf >= 0.9

    def test_utf8_bom_file(self, tmp_path: Path):
        f = tmp_path / "bom.txt"
        f.write_bytes(b"\xef\xbb\xbfhello")
        content, enc, _ = read_file_safe(f)
        assert content == "hello"
        assert enc == "utf-8-sig"

    def test_gb18030_file(self, tmp_path: Path):
        f = tmp_path / "gb.txt"
        f.write_bytes("中文测试".encode("gb18030"))
        content, enc, _ = read_file_safe(f)
        assert "中文测试" in content

    def test_non_existent_file_raises(self, tmp_path: Path):
        with pytest.raises((FileNotFoundError, OSError)):
            read_file_safe(tmp_path / "nope.txt")


class TestNormalizePath:
    """normalize_path tests."""

    def test_forward_slashes_on_unix(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("os.sep", "/")
        assert normalize_path("a\\b\\c") == "a/b/c"
        assert normalize_path("a/b/c") == "a/b/c"

    def test_backslashes_on_windows(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("os.sep", "\\")
        assert normalize_path("a/b/c") == "a\\b\\c"


class TestIsSupportedExtension:
    """is_supported_extension tests."""

    def test_java_is_supported(self):
        assert is_supported_extension("App.java") is True

    def test_yml_is_supported(self):
        assert is_supported_extension("config.yml") is True

    def test_exe_is_not_supported(self):
        assert is_supported_extension("binary.exe") is False

    def test_no_extension_not_supported(self):
        assert is_supported_extension("Makefile") is False

    def test_custom_extensions(self):
        assert is_supported_extension("config.conf", [".conf"]) is True
        assert is_supported_extension("config.toml", [".conf"]) is False


class TestIsBinaryFile:
    """is_binary_file tests."""

    def test_text_file_is_not_binary(self, tmp_path: Path):
        f = tmp_path / "text.txt"
        f.write_text("hello")
        assert is_binary_file(f) is False

    def test_binary_file_is_detected(self, tmp_path: Path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02")
        assert is_binary_file(f) is True

    def test_non_existent_file(self, tmp_path: Path):
        assert is_binary_file(tmp_path / "ghost.dat") is False
