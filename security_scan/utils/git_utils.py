"""Git operations utilities."""

from __future__ import annotations

import subprocess


def _git_cmd(cwd: str | None = None) -> list[str]:
    """Return base git command, optionally pointing to a repo directory."""
    if cwd:
        return ["git", "-C", cwd]
    return ["git"]


def get_staged_files(repo_path: str | None = None) -> list[str]:
    """Return list of staged file paths from ``git diff --cached --name-only``.

    Parameters
    ----------
    repo_path :
        If provided, run git from that directory (via ``git -C``).

    Returns an empty list if not in a git repository or if an error occurs.
    """
    try:
        result = subprocess.run(
            _git_cmd(repo_path) + ["diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except (FileNotFoundError, OSError):
        return []


def get_repo_root(repo_path: str | None = None) -> str:
    """Return the absolute path of the current git repository root.

    Returns an empty string if not in a git repository.
    """
    try:
        result = subprocess.run(
            _git_cmd(repo_path) + ["rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()
    except (FileNotFoundError, OSError):
        return ""


def is_staged_file(file_path: str) -> bool:
    """Check whether *file_path* is in the git staging area."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--", file_path],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and file_path in result.stdout.strip()
    except (FileNotFoundError, OSError):
        return False


def has_unresolved_conflicts() -> bool:
    """Return True if the repository has unresolved merge conflicts."""
    try:
        result = subprocess.run(
            ["git", "diff", "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        return "conflict" in result.stdout.lower()
    except (FileNotFoundError, OSError):
        return False
