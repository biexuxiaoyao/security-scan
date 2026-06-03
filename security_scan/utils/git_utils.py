"""Git operations utilities."""


def get_staged_files() -> list[str]:
    """Return list of staged file paths from git diff --cached."""
    ...


def get_repo_root() -> str:
    """Return the absolute path of the current git repository root."""
    ...
