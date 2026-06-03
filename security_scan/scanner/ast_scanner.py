"""AST scanner — uses tree-sitter and javalang for Java source analysis."""


class ASTScanner:
    """Parses Java AST and applies semantic security rules."""

    def __init__(self, config: dict):
        self.config = config

    def scan(self, file_path: str) -> list[dict]:
        """Scan a single .java file and return findings."""
        ...
