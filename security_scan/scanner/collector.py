"""File collector — gathers file lists under full or incremental scan modes."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterator

from security_scan.utils.file_utils import is_supported_extension
from security_scan.utils.git_utils import get_staged_files


class FileCollector:
    """Collects files to scan based on scan mode and ignore rules.

    Parameters
    ----------
    config :
        Full configuration dict (used for ``scan.exclude`` patterns).
    project_path :
        Project root path. Used for incremental scan to run git commands
        in the correct directory.
    """

    def __init__(self, config: dict, project_path: str | None = None):
        self.config = config
        self.project_path = project_path
        self._exclude_patterns = config.get("scan", {}).get("exclude", [])
        self._file_extensions = config.get("scan", {}).get("file_extensions", [])

    # ── full scan ──────────────────────────────────────────────

    def collect_full(self, path: str) -> list[str]:
        """Recursively collect all supported files under *path*.

        Skips directories matching ``scan.exclude`` patterns and binary files.
        """
        root = Path(path).resolve()
        if not root.is_dir():
            return []

        files: list[str] = []
        for abs_path in self._walk(root):
            rel = str(abs_path.relative_to(root))
            if self._is_excluded(rel):
                continue
            if is_supported_extension(rel, self._file_extensions):
                files.append(str(abs_path))
        return sorted(files)

    # ── incremental scan ───────────────────────────────────────

    def collect_incremental(self) -> list[str]:
        """Collect staged changed files via ``git diff --cached``.

        Only returns files with supported extensions (excludes binary files).

        Staged file paths (relative to repo root) are resolved to absolute
        paths using ``project_path`` so they can be opened by scanners.
        """
        staged = get_staged_files(repo_path=self.project_path)
        result: list[str] = []
        base = Path(self.project_path or "").resolve()
        for f in staged:
            if self._is_excluded(f):
                continue
            if is_supported_extension(f, self._file_extensions):
                abs_path = str(base / f)
                result.append(abs_path)
        return sorted(result)

    # ── internals ──────────────────────────────────────────────

    def _walk(self, root: Path) -> Iterator[Path]:
        """Yield all regular files under *root*."""
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                yield Path(dirpath) / fn

    def _is_excluded(self, rel_path: str) -> bool:
        """Check if *rel_path* matches any exclude pattern."""
        for pattern in self._exclude_patterns:
            p = pattern.rstrip("/")
            if fnmatch.fnmatch(rel_path, p):
                return True
            # Also match anything inside a directory pattern
            if fnmatch.fnmatch(rel_path, p + "/*"):
                return True
            # Check if the path starts with the pattern (directory prefix)
            if rel_path.startswith(p + "/"):
                return True
        return False
