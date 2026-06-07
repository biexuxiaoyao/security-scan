"""AST scanner — uses tree-sitter and javalang for Java source analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_scan.rules import RuleEngine
from security_scan.utils.file_utils import read_file_safe, is_binary_file
from security_scan.utils.encryption import check_encrypted_prefix

# ── lazy tree-sitter imports ──────────────────────────────────

_TREE_SITTER_AVAILABLE = False
_TREE_SITTER_PARSER: Any = None

_PASSWORD_KEYWORDS = frozenset({
    "password", "passwd", "pwd", "pass", "secret", "secret_key",
    "secretkey", "api_key", "apikey", "auth_token", "token",
    "private_key", "access_key", "connection_string",
})

_NON_SECRET_KEYWORDS = frozenset({
    "enabled", "debug", "port", "host", "timeout", "retry",
    "max", "min", "size", "limit", "count", "index", "mode",
    "name", "label", "title", "version", "locale", "timezone",
})


def _init_parser() -> bool:
    """Lazy-init the tree-sitter Java parser. Returns True if available."""
    global _TREE_SITTER_AVAILABLE, _TREE_SITTER_PARSER
    if _TREE_SITTER_AVAILABLE:
        return True
    try:
        import tree_sitter_java
        from tree_sitter import Language, Parser
        lang = Language(tree_sitter_java.language())
        _TREE_SITTER_PARSER = Parser(lang)
        _TREE_SITTER_AVAILABLE = True
        return True
    except Exception:
        _TREE_SITTER_AVAILABLE = False
        _TREE_SITTER_PARSER = None
        return False


# ── ASTScanner ────────────────────────────────────────────────


class ASTScanner:
    """Parses Java AST and applies semantic security rules.

    Uses tree-sitter as the primary parser, falling back to line-based
    regex scanning when tree-sitter is unavailable.
    """

    def __init__(self, config: dict):
        self.config = config
        self._encrypted_prefixes = config.get("encrypted_prefixes", [])

    def scan(self, file_path: str, rule_engine: RuleEngine) -> list[dict]:
        """Scan a single ``.java`` file and return findings.

        Tries tree-sitter AST parsing first; falls back to line-based
        regex scanning if tree-sitter is unavailable or parse fails.

        Parameters
        ----------
        file_path :
            Path to the Java source file.
        rule_engine :
            Initialized rule engine for matching.

        Returns
        -------
        list[dict]
            Findings from this file.
        """
        path = Path(file_path)
        if not path.is_file() or is_binary_file(file_path):
            return []

        try:
            content, _enc, _conf = read_file_safe(file_path)
        except (OSError, UnicodeDecodeError):
            return []

        # ── AST parse ──────────────────────────────────────────
        _init_parser()  # ensure lazy init
        if _TREE_SITTER_AVAILABLE:
            ast_findings = self._scan_ast(content, str(path), rule_engine)
            if ast_findings is not None:
                return ast_findings

        # ── fallback: line-based regex scan ────────────────────
        findings: list[dict] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            line_findings = rule_engine.scan_line(line, line_number, "java")
            for f in line_findings:
                f["file_path"] = str(path)
            findings.extend(line_findings)
        return findings

    # ── AST scan ─────────────────────────────────────────────

    def _scan_ast(self, source: str, file_path: str, rule_engine: RuleEngine) -> list[dict] | None:
        """Walk the AST and return findings.

        Returns ``None`` if the parse failed (triggers fallback).
        """
        source_bytes = source.encode("utf-8")
        try:
            tree = _TREE_SITTER_PARSER.parse(source_bytes)
        except Exception:
            return None

        root = tree.root_node
        if root is None:
            return None

        findings: list[dict] = []

        # Walk all field declarations and variable declarations
        self._walk_declarations(root, source_bytes, file_path, findings)

        # Also run line-based regex for non-field issues (comments, logs, etc.)
        # but skip lines already covered by AST findings to avoid duplicates
        ast_covered_lines = {f["line_number"] for f in findings}
        for line_number, line in enumerate(source.splitlines(), start=1):
            if line_number in ast_covered_lines:
                continue
            line_findings = rule_engine.scan_line(line, line_number, "java")
            for f in line_findings:
                f["file_path"] = file_path
            findings.extend(line_findings)

        return findings

    # ── declaration walker ───────────────────────────────────

    def _walk_declarations(
        self,
        node: Any,
        source_bytes: bytes,
        file_path: str,
        findings: list[dict],
    ) -> None:
        """Recursively walk the AST looking for field and variable declarations."""
        stack = [node]
        while stack:
            current = stack.pop()
            kind = current.type

            if kind == "field_declaration":
                self._check_field_declaration(current, source_bytes, file_path, findings)
            elif kind == "variable_declaration":
                self._check_variable_declaration(current, source_bytes, file_path, findings)

            # Push children in reverse order to maintain file order (optional)
            for child in reversed(current.children):
                stack.append(child)

    # ── field declaration analysis ───────────────────────────

    def _check_field_declaration(
        self,
        node: Any,
        source_bytes: bytes,
        file_path: str,
        findings: list[dict],
    ) -> None:
        """Analyze a ``field_declaration`` node for security issues."""
        # Extract variable name(s), type, and annotations
        vars_info = self._parse_field_declaration(node, source_bytes)
        if not vars_info:
            return

        var_name = vars_info["name"]
        var_type = vars_info["type"]
        value = vars_info["value"]
        annotations = vars_info["annotations"]
        line_number = node.start_point[0] + 1  # tree-sitter uses 0-indexed lines

        # ── Case 1: @Value annotation with default ────────────
        for ann in annotations:
            if ann["name"] == "Value":
                finding = self._check_value_annotation(
                    ann, var_name, var_type, file_path, source_bytes,
                )
                if finding:
                    findings.append(finding)

        # ── Case 2: direct assignment to password-related field ──
        if value is not None:
            finding = self._check_direct_assignment(
                var_name, var_type, value, line_number, file_path,
            )
            if finding:
                findings.append(finding)

    # ── variable declaration analysis (local variables) ──────

    def _check_variable_declaration(
        self,
        node: Any,
        source_bytes: bytes,
        file_path: str,
        findings: list[dict],
    ) -> None:
        """Analyze a ``variable_declaration`` node (local vars)."""
        # Get the type from the first child
        var_type = ""
        for child in node.children:
            if child.is_named:
                var_type = _node_text(child, source_bytes)
                break

        for child in node.children:
            if child.type == "variable_declarator":
                self._check_variable_declarator(
                    child, var_type, source_bytes, file_path, findings,
                )

    def _check_variable_declarator(
        self,
        node: Any,
        var_type: str,
        source_bytes: bytes,
        file_path: str,
        findings: list[dict],
    ) -> None:
        """Analyze a ``variable_declarator`` for ``var = "secret"``."""
        name = None
        value = None
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, source_bytes)
            elif child.type == "string_literal":
                value = _node_text(child, source_bytes)

        if name is None or value is None:
            return

        name_lower = name.lower()
        line_number = node.start_point[0] + 1

        # Only check password-related variable names
        if not any(kw in name_lower for kw in _PASSWORD_KEYWORDS):
            return

        if self._is_encrypted(value):
            findings.append({
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "LOW",
                "description": "Plaintext string literal assigned to a password-related variable.",
                "line_number": line_number,
                "matched_content": value,
                "confidence": 0.0,
                "file_path": file_path,
                "encrypted": True,
                "encrypted_prefix_matched": self._matched_prefix(value),
                "remediation": "This value is already encrypted. No action needed.",
            })
        else:
            findings.append({
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "CRITICAL" if len(value) >= 6 else "HIGH",
                "description": "Plaintext string literal assigned to a password-related variable.",
                "line_number": line_number,
                "matched_content": value,
                "confidence": 0.92,
                "file_path": file_path,
                "remediation": "Replace with environment variable or secret manager.",
            })

    # ── @Value annotation analysis ───────────────────────────

    def _check_value_annotation(
        self,
        ann: dict,
        var_name: str,
        var_type: str,
        file_path: str,
        source_bytes: bytes,
    ) -> dict | None:
        """Analyze a ``@Value`` annotation for potential leaks.

        ``@Value`` annotations follow the pattern:
          @Value("${property.name:default_value}")

        Where ``default_value`` is the fallback if the property is not set.
        This value is often mistakenly a plaintext password.
        """
        default_value = ann.get("default_value")
        if default_value is None:
            return None

        # Determine the line number from the annotation node
        line_number = ann["line"]

        # ── if configured as encrypted prefix → skip ────────
        if self._is_encrypted(default_value):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "LOW",
                "description": f"@{ann['name']} default value — already encrypted.",
                "line_number": line_number,
                "matched_content": default_value,
                "confidence": 0.0,
                "file_path": file_path,
                "encrypted": True,
                "encrypted_prefix_matched": self._matched_prefix(default_value),
                "remediation": "This value is already encrypted. No action needed.",
            }

        # ── type-based analysis ─────────────────────────────
        name_lower = var_name.lower()

        # Non-secret keywords in variable name → likely not a password
        if any(kw in name_lower for kw in _NON_SECRET_KEYWORDS):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "LOW",
                "description": f"@{ann['name']} default value — variable name suggests non-secret.",
                "line_number": line_number,
                "matched_content": default_value,
                "confidence": 0.10,
                "file_path": file_path,
                "_ast_marked_safe": True,
            }

        # Boolean/primitive type → not a password
        type_lower = var_type.lower()
        if type_lower in ("boolean", "bool", "int", "long", "double", "float"):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "LOW",
                "description": f"@{ann['name']} default value — type '{var_type}' is not a credential.",
                "line_number": line_number,
                "matched_content": default_value,
                "confidence": 0.05,
                "file_path": file_path,
                "_ast_marked_safe": True,
            }

        # Password-related variable name + string value → CRITICAL
        if any(kw in name_lower for kw in _PASSWORD_KEYWORDS):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "CRITICAL",
                "description": f"@{ann['name']} default value is a plaintext password.",
                "line_number": line_number,
                "matched_content": default_value,
                "confidence": 0.92,
                "file_path": file_path,
                "remediation": "Use environment variable or encrypted config source instead of @Value default.",
            }

        # Generic string value, non-password variable name → MEDIUM warning
        if _is_plausible_secret(default_value):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "MEDIUM",
                "description": f"@{ann['name']} default value looks like a credential.",
                "line_number": line_number,
                "matched_content": default_value,
                "confidence": 0.60,
                "file_path": file_path,
                "remediation": "Verify this @Value default is not a plaintext credential.",
            }

        return None

    # ── direct assignment analysis ──────────────────────────

    def _check_direct_assignment(
        self,
        var_name: str,
        var_type: str,
        value: str,
        line_number: int,
        file_path: str,
    ) -> dict | None:
        """Check ``private String x = \"secret\"`` patterns."""
        name_lower = var_name.lower()
        type_lower = var_type.lower()

        # Skip boolean/numeric types
        if type_lower in ("boolean", "bool", "int", "long", "double", "float"):
            return None

        # Check password-related keywords in variable name
        if not any(kw in name_lower for kw in _PASSWORD_KEYWORDS):
            return None

        if self._is_encrypted(value):
            return {
                "rule_id": "java_plaintext_password",
                "rule_name": "Java plaintext password",
                "severity": "LOW",
                "description": "Password-related field — value is encrypted.",
                "line_number": line_number,
                "matched_content": value,
                "confidence": 0.0,
                "file_path": file_path,
                "encrypted": True,
                "encrypted_prefix_matched": self._matched_prefix(value),
                "remediation": "Value is encrypted. No action needed.",
            }

        return {
            "rule_id": "java_plaintext_password",
            "rule_name": "Java plaintext password",
            "severity": "CRITICAL" if len(value) >= 6 else "HIGH",
            "description": f"Plaintext string literal assigned to '{var_name}'.",
            "line_number": line_number,
            "matched_content": value,
            "confidence": 0.92,
            "file_path": file_path,
            "remediation": "Replace with environment variable or secret manager.",
        }

    # ── AST parsing helpers ──────────────────────────────────

    @staticmethod
    def _parse_field_declaration(
        node: Any,
        source_bytes: bytes,
    ) -> dict | None:
        """Extract details from a ``field_declaration`` AST node.

        Returns a dict with keys: ``name``, ``type``, ``value``, ``annotations``.
        """
        var_name = None
        var_type = None
        value = None
        annotations: list[dict] = []

        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "annotation":
                        ann_info = _parse_annotation(mod, source_bytes)
                        if ann_info:
                            annotations.append(ann_info)
            elif child.is_named and child.type in (
                "type_identifier", "integral_type", "floating_point_type",
                "boolean_type", "void_type",
            ):
                var_type = _node_text(child, source_bytes)
            elif child.type == "variable_declarator":
                var_name = _parse_variable_declarator_name(child, source_bytes)
                value = _parse_variable_declarator_value(child, source_bytes)

        if var_name is None:
            return None

        return {
            "name": var_name,
            "type": var_type or "unknown",
            "value": value,
            "annotations": annotations,
        }

    # ── encrypted prefix helpers ─────────────────────────────

    def _is_encrypted(self, value: str) -> bool:
        """Check if *value* starts with a configured encrypted prefix."""
        if not self._encrypted_prefixes:
            return False
        is_enc, _prefix = check_encrypted_prefix(value, self._encrypted_prefixes)
        return is_enc

    def _matched_prefix(self, value: str) -> str:
        """Return the matched encrypted prefix or empty string."""
        _is_enc, prefix = check_encrypted_prefix(value, self._encrypted_prefixes)
        return prefix or ""


# ── module-level helpers ──────────────────────────────────────


def _node_text(node: Any, source_bytes: bytes) -> str:
    """Extract the source text for an AST node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _parse_annotation(node: Any, source_bytes: bytes) -> dict | None:
    """Parse an annotation node (e.g. ``@Value(...)``) into a structured dict.

    Returns::

        {
            "name": "Value",
            "argument": "${db.password:password123}",
            "default_value": "password123",   # extracted from "${key:default}"
            "line": <line-number>,
        }
    """
    name = None
    argument = None
    default_value = None
    line = node.start_point[0] + 1

    for child in node.children:
        if child.type == "identifier":
            name = _node_text(child, source_bytes)
        elif child.type == "annotation_argument_list":
            # Extract the string literal inside the parentheses
            for arg_child in child.children:
                if arg_child.type == "string_literal":
                    raw = _node_text(arg_child, source_bytes)
                    # Strip quotes
                    argument = raw.strip("\"")
                    # Try to extract default from "${key:default}"
                    default_value = _extract_default_from_el(argument)

    if name is None:
        return None

    return {
        "name": name,
        "argument": argument,
        "default_value": default_value,
        "line": line,
    }


def _extract_default_from_el(el_expr: str) -> str | None:
    """Extract default value from a SpEL expression ``${key:default}``.

    Examples::

        "${db.password:password123}"  →  "password123"
        "${feature.enabled:true}"      →  "true"
        "${max.retry:3}"               →  "3"
        "${app.version:1.2.3}"         →  "1.2.3"
        "${api.base-url}"              →  None (no default)
        "hardcoded string"             →  None (not a SpEL expr)
    """
    # Match ${...} expressions
    if not (el_expr.startswith("${") and ":" in el_expr):
        return None

    # Extract the default value after the last ':'
    # e.g., "${db.password:password123}" → "password123"
    # e.g., "${feature.enabled:true}" → "true"
    colon_idx = el_expr.rfind(":")
    if colon_idx < 0:
        return None
    default_part = el_expr[colon_idx + 1:]
    # Strip closing brace if present
    if default_part.endswith("}"):
        default_part = default_part[:-1]
    return default_part.strip() or None


def _parse_variable_declarator_name(node: Any, source_bytes: bytes) -> str | None:
    """Extract the variable name from a ``variable_declarator`` node."""
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child, source_bytes)
    return None


def _parse_variable_declarator_value(node: Any, source_bytes: bytes) -> str | None:
    """Extract the string literal value from a ``variable_declarator`` node.

    Handles::

        name = "value"
        name = OTHER_CONSTANT
    """
    for child in node.children:
        if child.type == "string_literal":
            raw = _node_text(child, source_bytes)
            return raw.strip("\"")
        # Could also be an identifier reference — skip those
    return None


def _is_plausible_secret(value: str) -> bool:
    """Heuristic: does the string look like a plausible credential?"""
    if len(value) < 5:
        return False
    # Long string containing mixed characters (keys, tokens, base64)
    if len(value) >= 20:
        return True
    # Password-like patterns
    value_lower = value.lower()
    if value_lower in ("password", "secret", "admin", "root", "test123", "changeme", "passw0rd"):
        return True
    return False
