"""Tests for security_scan.hook.installer."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from security_scan.hook.installer import HookInstaller


class TestHookInstaller:
    def test_install_creates_hook(self, tmp_path: Path):
        """Install creates a .git/hooks/pre-commit in a git repo."""
        # Init a temporary git repo
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir()

        # We need to patch get_repo_root to return this temp dir
        installer = HookInstaller({})
        installer._resolve_hook_path = lambda global_hook=False: repo / ".git" / "hooks" / "pre-commit"

        result = installer.install()
        assert result is True
        hook = repo / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        assert hook.stat().st_mode & stat.S_IXUSR

    def test_install_idempotent(self, tmp_path: Path):
        """Installing twice should not duplicate content."""
        repo = tmp_path / "repoidem"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir()

        installer = HookInstaller({})
        installer._resolve_hook_path = lambda global_hook=False: repo / ".git" / "hooks" / "pre-commit"

        installer.install()
        content_after_first = (repo / ".git" / "hooks" / "pre-commit").read_text()

        installer.install()
        content_after_second = (repo / ".git" / "hooks" / "pre-commit").read_text()

        assert content_after_first == content_after_second

    def test_uninstall_removes_hook(self, tmp_path: Path):
        repo = tmp_path / "repouninst"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir()

        installer = HookInstaller({})
        installer._resolve_hook_path = lambda global_hook=False: repo / ".git" / "hooks" / "pre-commit"

        installer.install()
        assert (repo / ".git" / "hooks" / "pre-commit").is_file()

        installer.uninstall()
        assert not (repo / ".git" / "hooks" / "pre-commit").is_file()

    def test_disable_renames_hook(self, tmp_path: Path):
        repo = tmp_path / "repodis"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir()

        installer = HookInstaller({})
        installer._resolve_hook_path = lambda global_hook=False: repo / ".git" / "hooks" / "pre-commit"

        installer.install()
        installer.disable()

        assert not (repo / ".git" / "hooks" / "pre-commit").is_file()
        assert (repo / ".git" / "hooks" / "pre-commit.disabled").is_file()

        installer.enable()
        assert (repo / ".git" / "hooks" / "pre-commit").is_file()
        assert not (repo / ".git" / "hooks" / "pre-commit.disabled").is_file()

    def test_smart_merge_preserves_existing_hook(self, tmp_path: Path):
        repo = tmp_path / "repomerg"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir()
        existing_hook = repo / ".git" / "hooks" / "pre-commit"
        existing_hook.write_text("#!/bin/sh\necho 'existing hook'\n")
        existing_hook.chmod(0o755)

        installer = HookInstaller({})
        installer._resolve_hook_path = lambda global_hook=False: existing_hook

        installer.install()
        content = existing_hook.read_text()
        assert "existing hook" in content
        assert HookInstaller.MARKER_LINE in content
