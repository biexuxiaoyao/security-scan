"""File collector — gathers file lists under full or incremental scan modes."""


class FileCollector:
    """Collects files to scan based on scan mode and ignore rules."""

    def __init__(self, config: dict):
        self.config = config

    def collect_full(self, path: str) -> list[str]:
        """Collect all supported files under *path* for full scan."""
        ...

    def collect_incremental(self) -> list[str]:
        """Collect staged changed files via git diff for incremental scan."""
        ...
