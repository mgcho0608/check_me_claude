"""spec-check 테스트 — scenario spec YAML 유효성 검사."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from check_me.cli_commands.cmd_spec_check import _KNOWN_FAMILIES, _REQUIRED_SPEC_FIELDS


def _write_spec(tmp_path: Path, content: dict, filename: str = "spec.yaml") -> Path:
    path = tmp_path / filename
    path.write_text(yaml.dump(content), encoding="utf-8")
    return path


def test_valid_spec(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "name": "test_spec",
        "description": "A test scenario spec",
        "candidate_families": ["RESULT_NOT_ENFORCED", "ACTION_BEFORE_REQUIRED_CHECK"],
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_missing_required_field(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "description": "missing name and candidate_families",
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code != 0
    assert "missing required field" in result.output


def test_unknown_candidate_family(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "name": "test",
        "description": "test",
        "candidate_families": ["NONEXISTENT_FAMILY"],
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code != 0
    assert "unknown candidate_family" in result.output


def test_duplicate_candidate_family(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "name": "test",
        "description": "test",
        "candidate_families": ["RESULT_NOT_ENFORCED", "RESULT_NOT_ENFORCED"],
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code != 0
    assert "duplicate" in result.output


def test_empty_candidate_families(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "name": "test",
        "description": "test",
        "candidate_families": [],
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code != 0
    assert "empty" in result.output


def test_invalid_profile_ref(tmp_path):
    from click.testing import CliRunner
    from check_me.cli_commands.cmd_spec_check import spec_check

    spec = {
        "name": "test",
        "description": "test",
        "candidate_families": ["RESULT_NOT_ENFORCED"],
        "profile_ref": "nonexistent_profile_xyz",
    }
    spec_path = _write_spec(tmp_path, spec)

    runner = CliRunner()
    result = runner.invoke(spec_check, ["--scenario-spec", str(spec_path)])
    assert result.exit_code != 0
    assert "profile_ref" in result.output


def test_valid_known_families_constant():
    """_KNOWN_FAMILIES가 실제 profile registry family를 포함하는지 확인."""
    from check_me.profiles.registry import ProfileRegistry
    registry = ProfileRegistry()
    all_profile_families: set[str] = set()
    for p in registry.all():
        all_profile_families.update(p.enabled_candidate_families)

    missing = all_profile_families - _KNOWN_FAMILIES
    assert not missing, f"Profile families not in spec-check known list: {missing}"
