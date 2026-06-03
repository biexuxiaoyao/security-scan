"""Whitelist filter — suppresses false positives based on user-defined rules."""


class WhitelistFilter:
    """Filters findings against project-level and global whitelist entries."""

    def filter(self, findings: list[dict]) -> list[dict]:
        """Remove findings that match whitelist rules."""
        ...
