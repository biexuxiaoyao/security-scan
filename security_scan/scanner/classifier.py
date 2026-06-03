"""File classifier — routes files to the appropriate scanner by extension."""

from __future__ import annotations

from pathlib import Path


class FileClassifier:
    """Maps file extensions to scan strategies.

    Built-in mapping (can be extended via config ``file_formats``):
        ``.java`` → ``"ast"``
        ``.xml``, ``.json``, ``.yml``, ``.yaml``,
        ``.properties``, ``.txt``, ``.md`` → ``"regex"``
    """

    EXTENSION_MAP: dict[str, str] = {
        ".java": "ast",
        ".xml": "regex",
        ".json": "regex",
        ".yml": "regex",
        ".yaml": "regex",
        ".properties": "regex",
        ".txt": "regex",
        ".md": "regex",
    }

    def __init__(self, config: dict):
        self.config = config
        # Load custom file formats from config
        for fmt in config.get("file_formats", []):
            strategy = fmt.get("scan_strategy", "regex")
            for ext in fmt.get("extensions", []):
                self.EXTENSION_MAP[ext.lower()] = strategy

    def classify(self, file_path: str) -> str:
        """Return scan strategy name for *file_path*.

        Returns ``"skip"`` for unsupported file types.
        """
        suffix = Path(file_path).suffix.lower()
        return self.EXTENSION_MAP.get(suffix, "skip")
