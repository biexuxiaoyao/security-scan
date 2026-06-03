"""Configuration loader — merges project .security-scan.yml with global defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


_DEFAULT_CONFIG: dict[str, Any] = {
    "scan": {
        "include": ["src/", "config/"],
        "exclude": ["target/", "build/", "node_modules/", ".git/"],
        "file_extensions": [
            ".java", ".xml", ".json", ".yml", ".yaml",
            ".properties", ".txt", ".md",
        ],
    },
    "severity": {
        "block_on_commit": ["CRITICAL", "HIGH"],
        "block_on_ci": ["CRITICAL"],
        "min_confidence_to_report": 0.50,
        "min_confidence_to_block": 0.70,
    },
    "encrypted_prefixes": [],
    "custom_rules": [],
    "file_formats": [],
    "ai": {
        "enabled": False,
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key_env": "SECURITY_SCAN_AI_KEY",
        "base_url": "https://api.openai.com/v1",
        "timeout": 10,
        "max_retries": 3,
        "batch_size": 20,
        "confidence_threshold": 0.7,
        "fallback_on_error": "keep_original",
    },
    "pip": {
        "index_url": "",
        "trusted_host": "",
        "extra_index_urls": [],
        "cert": "",
        "timeout": 30,
        "retries": 3,
    },
    "ci": {
        "enabled": False,
        "block_on": ["CRITICAL"],
        "output_format": "json",
        "report_artifact": "security-report.json",
        "max_scan_time": 300,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


class ConfigLoader:
    """Loads and merges configuration from multiple sources.

    Priority (highest → lowest):
      1. CLI arguments (passed programmatically)
      2. Project-level ``.security-scan.yml``
      3. Global ``~/.security-scan/config.yml``
      4. Built-in defaults
    """

    DEFAULT_CONFIG_PATH = ".security-scan.yml"
    GLOBAL_CONFIG_DIR = Path.home() / ".security-scan"
    GLOBAL_CONFIG_PATH = GLOBAL_CONFIG_DIR / "config.yml"

    def __init__(self, project_path: str | None = None):
        self.project_path = project_path or os.getcwd()

    # ── public API ──────────────────────────────────────────────

    def load(self, cli_overrides: dict | None = None) -> dict:
        """Load config from all sources and return merged result.

        Parameters
        ----------
        cli_overrides :
            CLI-level overrides (highest priority).
        """
        config = dict(_DEFAULT_CONFIG)                     # 4. defaults
        config = _deep_merge(config, self._load_global())  # 3. global
        config = _deep_merge(config, self._load_project()) # 2. project
        if cli_overrides:
            config = _deep_merge(config, cli_overrides)    # 1. CLI
        return config

    @classmethod
    def dump_defaults(cls) -> str:
        """Return a YAML string of the default config (for ``--generate-config``)."""
        return yaml.dump(_DEFAULT_CONFIG, default_flow_style=False, sort_keys=False)

    # ── internal loaders ───────────────────────────────────────

    def _load_global(self) -> dict:
        """Load ``~/.security-scan/config.yml`` if present."""
        path = self.GLOBAL_CONFIG_PATH
        if path.is_file():
            return self._read_yaml(path)
        return {}

    def _load_project(self) -> dict:
        """Load ``.security-scan.yml`` from the project root."""
        path = Path(self.project_path) / self.DEFAULT_CONFIG_PATH
        if path.is_file():
            return self._read_yaml(path)
        return {}

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _read_yaml(path: Path) -> dict:
        """Safely read a YAML file, returning empty dict on failure."""
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                return data if isinstance(data, dict) else {}
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            return {}
