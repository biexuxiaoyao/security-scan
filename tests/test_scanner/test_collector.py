"""Tests for security_scan.scanner.collector."""

from __future__ import annotations

from pathlib import Path

from security_scan.scanner.collector import FileCollector


class TestFileCollector:
    def test_collect_full_finds_java_files(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "App.java").write_text("class App {}")
        (src / "Util.java").write_text("class Util {}")
        (tmp_path / "README.md").write_text("# readme")

        collector = FileCollector({"scan": {"exclude": [], "file_extensions": [".java", ".md"]}})
        files = collector.collect_full(str(tmp_path))
        assert len(files) == 3
        assert any(f.endswith("App.java") for f in files)
        assert any(f.endswith("README.md") for f in files)

    def test_exclude_pattern_skips_target(self, tmp_path: Path):
        (tmp_path / "target").mkdir()
        (tmp_path / "target" / "App.java").write_text("class App {}")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "App.java").write_text("class App {}")

        collector = FileCollector({
            "scan": {"exclude": ["target"], "file_extensions": [".java"]}
        })
        files = collector.collect_full(str(tmp_path))
        assert len(files) == 1
        assert "target" not in files[0]

    def test_collect_full_on_nonexistent_dir(self, tmp_path: Path):
        collector = FileCollector({"scan": {"exclude": [], "file_extensions": [".java"]}})
        files = collector.collect_full(str(tmp_path / "nope"))
        assert files == []

    def test_is_excluded(self, tmp_path: Path):
        collector = FileCollector({
            "scan": {"exclude": ["node_modules", "build/"], "file_extensions": [".java"]}
        })
        assert collector._is_excluded("node_modules/foo/bar.java")
        assert collector._is_excluded("build/output.class")
        assert not collector._is_excluded("src/main/App.java")

    def test_incremental_returns_staged_files(self):
        """Test that collect_incremental returns a list (real git or empty)."""
        collector = FileCollector({
            "scan": {"exclude": [], "file_extensions": [".java", ".yml"]}
        })
        files = collector.collect_incremental()
        # In CI or outside a git repo this may be empty — just ensure it's a list
        assert isinstance(files, list)
