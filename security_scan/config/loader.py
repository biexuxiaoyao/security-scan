"""Configuration loader — merges project .security-scan.yml with global defaults."""

from pathlib import Path


class ConfigLoader:
    """Loads and merges configuration from multiple sources."""

    DEFAULT_CONFIG_PATH = ".security-scan.yml"
    GLOBAL_CONFIG_DIR = Path.home() / ".security-scan"
    GLOBAL_CONFIG_PATH = GLOBAL_CONFIG_DIR / "config.yml"

    def load(self, project_path: str | None = None) -> dict:
        """Load config from global + project sources; return merged dict."""
        ...

    def load_project_config(self, project_path: str) -> dict:
        """Load .security-scan.yml from the project root."""
        ...

    def load_global_config(self) -> dict:
        """Load ~/.security-scan/config.yml if it exists."""
        ...
