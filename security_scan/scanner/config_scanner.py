"""Config-driven config file scanner — structured key-value analysis.

Applies configurable key matching, whitelist filtering, and value
validation to yml/yaml/properties configuration files.

For YAML files, uses PyYAML's ``compose()`` to preserve line numbers and
build full dot-separated key paths (e.g. ``spring.datasource.password``).
For ``.properties`` files, falls back to line-by-line ``key=value`` parsing.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

from security_scan.utils.encryption import check_encrypted_prefix
from security_scan.utils.file_utils import read_file_safe, is_binary_file


def _is_excluded(file_path: str, exclude_patterns: list[str]) -> bool:
    """Return True if *file_path* matches any exclude glob pattern."""
    name = Path(file_path).name
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def _is_yaml_file(file_path: str) -> bool:
    """Return True if the file is a YAML file by extension."""
    return Path(file_path).suffix.lower() in (".yml", ".yaml")


def _parse_yaml_key_values(content: str) -> list[tuple[str, str, int]]:
    """Parse YAML content using ``yaml.compose()`` for line-number accuracy.

    Returns a list of ``(full_dotted_key, value, 1-based_line_number)`` tuples
    for every scalar leaf node in the YAML tree.  Returns an empty list on
    parse failure.
    """
    try:
        node = yaml.compose(content)
    except yaml.YAMLError:
        return []

    if node is None:
        return []

    results: list[tuple[str, str, int]] = []

    def _walk(n: yaml.Node, prefix: str) -> None:
        if isinstance(n, yaml.MappingNode):
            for key_node, val_node in n.value:
                if isinstance(key_node, yaml.ScalarNode):
                    seg = str(key_node.value)
                    full = f"{prefix}.{seg}" if prefix else seg
                    if isinstance(val_node, yaml.ScalarNode):
                        # line is 0-based in yaml, convert to 1-based
                        line = key_node.start_mark.line + 1
                        results.append((full, str(val_node.value), line))
                    elif isinstance(val_node, (yaml.MappingNode, yaml.SequenceNode)):
                        _walk(val_node, full)
                elif isinstance(n, yaml.SequenceNode):
                    for i, item in enumerate(n.value):
                        _walk(item, f"{prefix}[{i}]")

    _walk(node, "")
    return results


def _try_parse_key_value(line: str) -> tuple[str, str] | None:
    """Try to parse a config file line into (key, value).

    Handles ``key=value`` (properties) and ``key: value`` (yaml) formats.
    Returns ``None`` for comments, blank lines, or unparseable lines.
    """
    stripped = line.strip()

    # Skip comments and blank lines
    if not stripped or stripped.startswith(("#", "!", "//", "--")):
        return None

    # YAML/JSON inline: ``key: value``
    colon_idx = stripped.find(":")
    eq_idx = stripped.find("=")

    if colon_idx >= 0 and (eq_idx < 0 or colon_idx < eq_idx):
        key = stripped[:colon_idx].strip()
        value = stripped[colon_idx + 1:].strip()
    elif eq_idx >= 0:
        key = stripped[:eq_idx].strip()
        value = stripped[eq_idx + 1:].strip()
    else:
        return None  # not a key-value line

    if not key or not value:
        return None

    # Strip surrounding quotes
    value = value.strip("\"'")
    key = key.strip("\"'")

    return (key, value)


def _is_asterisk_masked(value: str) -> bool:
    """Return True if the value consists entirely of ``*`` characters."""
    return bool(value) and all(ch == "*" for ch in value)


def _matches_any(value: str, patterns: list[re.Pattern]) -> bool:
    """Return True if *value* matches any compiled pattern."""
    for pat in patterns:
        if pat.search(value):
            return True
    return False


class ConfigKeyValueScanner:
    """Structured key-value scanner for configuration files.

    Reads key patterns, whitelists, and value validation rules from config.
    Only scans yml/yaml/properties files (caller should pre-filter).
    """

    def __init__(self, config: dict):
        raw = config.get("config_file_secrets", {})
        self.enabled = raw.get("enabled", True)

        # File exclusion patterns (glob)
        self.exclude_patterns: list[str] = raw.get("exclude_patterns", [])

        # Key matching rules
        self.key_rules: list[dict[str, Any]] = raw.get("key_rules", [])

        # Compiled key whitelist
        self.key_whitelist: list[re.Pattern] = [
            re.compile(p) for p in raw.get("key_whitelist", [])
        ]

        # Value encrypted prefixes (not regex — string prefix match)
        self.value_encrypted_prefixes: list[str] = raw.get(
            "value_encrypted_prefixes", []
        )

        # Value placeholder patterns (compiled regex)
        self.value_placeholder_patterns: list[re.Pattern] = [
            re.compile(p)
            for p in raw.get("value_placeholder_patterns", [])
        ]

        # Compile the key rule patterns (each rule has multiple patterns)
        self._compiled_rules: list[dict[str, Any]] = []
        for rule in self.key_rules:
            compiled_pats = [
                re.compile(p) for p in rule.get("patterns", [])
            ]
            # Also add a generic catch-all from the rule's id
            self._compiled_rules.append({
                "id": rule.get("id", "config_unknown"),
                "name": rule.get("name", "Config secret"),
                "severity": rule.get("severity", "HIGH"),
                "patterns": compiled_pats,
            })

    def scan(self, file_path: str, content: str | None = None) -> list[dict]:
        """Scan a single config file for credential-in-key issues.

        Parameters
        ----------
        file_path :
            Path to the config file.
        content :
            Pre-read file content.  If provided, skips ``read_file_safe()``
            — used when the caller has already read the file.

        Uses YAML-aware parsing for ``.yml``/``.yaml`` files (preserves
        nested key paths and line numbers), line-by-line for ``.properties``.

        Returns
        -------
        list[dict]
            Findings from this file (may be empty).
        """
        if not self.enabled:
            return []

        path = Path(file_path)

        # Exclude files matching exclude patterns
        if _is_excluded(file_path, self.exclude_patterns):
            return []

        if not path.is_file() or is_binary_file(file_path):
            return []

        if content is None:
            try:
                content, _enc, _conf = read_file_safe(file_path)
            except (OSError, UnicodeDecodeError):
                return []

        findings: list[dict] = []

        if _is_yaml_file(file_path):
            key_values = _parse_yaml_key_values(content)
            for full_key, value, line_number in key_values:
                result = self._scan_kv(full_key, value, file_path, line_number)
                if result:
                    findings.append(result)
        else:
            # Properties file — line by line
            for line_number, line in enumerate(content.splitlines(), start=1):
                kv = _try_parse_key_value(line)
                if kv is None:
                    continue
                key, value = kv
                result = self._scan_kv(key, value, file_path, line_number)
                if result:
                    findings.append(result)

        return findings

    def _scan_kv(
        self, key: str, value: str, file_path: str, line_number: int
    ) -> dict | None:
        """Analyse a single (key, value) pair from a config file.

        1. Check key against sensitive patterns.
        2. If matched, check key whitelist.
        3. Validate value (encrypted / masked / placeholder).
        4. Return finding or None.
        """
        # Step 1: Find which key rule (if any) matches this key
        matched_rule = self._match_key_rule(key)
        if matched_rule is None:
            return None

        # Step 2: Check key whitelist
        if self._is_key_whitelisted(key):
            return None

        # Step 3: Validate value
        encrypted = False
        encrypted_prefix = None
        is_safe_value = False

        # Check encrypted prefixes
        is_enc, encrypted_prefix = check_encrypted_prefix(value, self.value_encrypted_prefixes)
        if is_enc:
            encrypted = True

        # Check asterisk masking (****)
        if _is_asterisk_masked(value):
            is_safe_value = True

        # Check placeholder patterns: $(), ${}, <>, @xx@
        if _matches_any(value, self.value_placeholder_patterns):
            is_safe_value = True

        # Build finding
        finding: dict[str, Any] = {
            "rule_id": matched_rule["id"],
            "rule_name": matched_rule["name"],
            "severity": "LOW" if (encrypted or is_safe_value) else matched_rule["severity"],
            "description": (
                f"{matched_rule['name']}: key '{key}' uses "
                + ("an encrypted value." if encrypted
                   else "a placeholder value." if is_safe_value
                   else f"a plaintext value '{value}'.")),
            "remediation": (
                "Value is already encrypted or references an external source. No action needed."
                if encrypted or is_safe_value
                else "Replace the plaintext value with an encrypted value using BEE_, "
                       "ENC(, {cipher} encryption, or a placeholder reference like ${env.VAR}."),
            "line_number": line_number,
            "matched_content": f"{key}={value}",
            "confidence": 0.1 if is_safe_value else (0.0 if encrypted else 0.90),
            "file_path": file_path,
            "config_key": key,
            "config_value_masked": True,
        }

        if encrypted:
            finding["encrypted"] = True
            finding["encrypted_prefix_matched"] = encrypted_prefix
        if is_safe_value:
            finding["_safe_placeholder"] = True

        return finding

    def _scan_line(
        self, line: str, file_path: str, line_number: int
    ) -> dict | None:
        """Scan a single config file line (DEPRECATED — kept for backward compat).

        Delegates to ``_scan_kv`` after line-parsing.
        """
        kv = _try_parse_key_value(line)
        if kv is None:
            return None
        return self._scan_kv(kv[0], kv[1], file_path, line_number)

    # ── internals ─────────────────────────────────────────────

    def _match_key_rule(self, key: str) -> dict[str, Any] | None:
        """Return the first key rule whose patterns match *key*."""
        for rule in self._compiled_rules:
            for pat in rule["patterns"]:
                if pat.search(key):
                    return rule
        return None

    def _is_key_whitelisted(self, key: str) -> bool:
        """Return True if *key* matches any whitelist pattern."""
        for pat in self.key_whitelist:
            if pat.search(key):
                return True
        return False
