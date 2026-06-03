"""Tests for security_scan.config.loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_scan.config.loader import ConfigLoader


class TestConfigLoader:
    """ConfigLoader unit tests."""

    def test_defaults_are_returned_when_no_config_exists(self, temp_project_no_config: Path):
        """Loading from a project without a config file returns defaults."""
        loader = ConfigLoader(str(temp_project_no_config))
        config = loader.load()
        assert config["severity"]["block_on_commit"] == ["CRITICAL", "HIGH"]
        assert config["encrypted_prefixes"] == []
        assert config["ai"]["enabled"] is False
        assert config["ci"]["enabled"] is False

    def test_project_config_overrides_defaults(self, temp_project: Path):
        """Project-level .security-scan.yml overrides built-in defaults."""
        loader = ConfigLoader(str(temp_project))
        config = loader.load()
        assert config["scan"]["include"] == ["src/"]
        assert config["encrypted_prefixes"] == ["BEE_", "ENC("]

    def test_cli_overrides_have_highest_priority(self, temp_project: Path):
        """CLI-level overrides beat project-level and defaults."""
        loader = ConfigLoader(str(temp_project))
        config = loader.load(cli_overrides={"scan": {"include": ["custom/"]}})
        assert config["scan"]["include"] == ["custom/"]

    def test_encrypted_prefixes_are_merged(self, temp_project: Path):
        """encrypted_prefixes from project config are available in loaded config."""
        loader = ConfigLoader(str(temp_project))
        config = loader.load()
        assert "BEE_" in config["encrypted_prefixes"]
        assert "ENC(" in config["encrypted_prefixes"]

    def test_global_config_loaded_when_present(self, temp_project: Path):
        """Global ~/.security-scan/config.yml is loaded when present."""
        global_dir = temp_project / ".security-scan"
        global_dir.mkdir()
        global_cfg = global_dir / "config.yml"
        global_cfg.write_text("severity:\n  min_confidence_to_report: 0.3\n")

        loader = ConfigLoader(str(temp_project))
        loader.GLOBAL_CONFIG_DIR = global_dir
        loader.GLOBAL_CONFIG_PATH = global_cfg
        config = loader.load()
        assert config["severity"]["min_confidence_to_report"] == 0.3

    def test_dump_defaults_returns_valid_yaml(self):
        """dump_defaults() returns well-formed YAML with expected keys."""
        yaml_str = ConfigLoader.dump_defaults()
        assert "encrypted_prefixes:" in yaml_str
        assert "severity:" in yaml_str
        assert "ci:" in yaml_str

    def test_missing_yaml_file_returns_empty_dict(self, temp_project_no_config: Path):
        """_read_yaml on a non-existent file returns {}."""
        result = ConfigLoader._read_yaml(temp_project_no_config / "nonexistent.yml")
        assert result == {}
