"""Custom rule loader — loads user-defined rules from .security-scan.yml."""


class CustomRuleLoader:
    """Loads and validates custom scanning rules."""

    def load(self, config: dict) -> list[dict]:
        """Parse custom rules from configuration."""
        ...
