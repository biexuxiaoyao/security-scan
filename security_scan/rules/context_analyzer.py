"""Context analyzer — AST-level semantic analysis to reduce false positives."""


class ContextAnalyzer:
    """Analyzes code context (annotations, variable names, data flow) to
    distinguish real secrets from non-sensitive values."""

    def analyze(self, finding: dict, ast_context: dict) -> dict:
        """Apply context analysis to a finding and return updated confidence/severity."""
        ...
