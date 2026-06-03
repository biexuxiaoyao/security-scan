"""File classifier — routes files to the appropriate scanner by extension."""


class FileClassifier:
    """Maps file extensions to scan strategies."""

    EXTENSION_MAP = {
        ".java": "ast",
        ".xml": "regex",
        ".json": "regex",
        ".yml": "regex",
        ".yaml": "regex",
        ".properties": "regex",
        ".txt": "regex",
        ".md": "regex",
    }

    def classify(self, file_path: str) -> str:
        """Return scan strategy name for *file_path*."""
        ...
