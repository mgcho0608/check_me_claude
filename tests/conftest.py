"""pytest 공통 fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent / "rules"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture
def registry_path(rules_dir: Path) -> Path:
    return rules_dir / "c_cpp_registry.yaml"


@pytest.fixture
def update_fixture_dir(fixture_dir: Path) -> Path:
    return fixture_dir / "update_integrity"


@pytest.fixture
def auth_fixture_dir(fixture_dir: Path) -> Path:
    return fixture_dir / "auth_session"


@pytest.fixture
def buffer_fixture_dir(fixture_dir: Path) -> Path:
    return fixture_dir / "buffer_safety"
