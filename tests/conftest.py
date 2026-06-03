"""Shared fixtures for security-scan tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest
import yaml


@pytest.fixture
def temp_project() -> Generator[Path, None, None]:
    """Create a temporary project directory with a .security-scan.yml."""
    with tempfile.TemporaryDirectory(prefix="secscan-") as tmp:
        project = Path(tmp)
        config = {
            "scan": {"include": ["src/"], "exclude": ["tests/"]},
            "encrypted_prefixes": ["BEE_", "ENC("],
        }
        with open(project / ".security-scan.yml", "w", encoding="utf-8") as f:
            yaml.dump(config, f)
        yield project


@pytest.fixture
def temp_project_no_config() -> Generator[Path, None, None]:
    """Create a temporary project directory with no config file."""
    with tempfile.TemporaryDirectory(prefix="secscan-") as tmp:
        yield Path(tmp)


@pytest.fixture
def fixture_dir() -> Path:
    """Return the absolute path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"
