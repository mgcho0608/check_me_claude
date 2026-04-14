"""Validator 테스트 — 아티팩트 일관성 검증."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.config import LLMConfig
from check_me.core.indexer import Indexer
from check_me.core.security_model import SecurityModelBuilder
from check_me.core.validator import Validator
from check_me.modes.code_mode import CodeMode
from check_me.modes.scenario_mode import ScenarioMode


def test_validator_passes_after_index(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    ok, issues = Validator(output_dir=tmp_path).run()
    assert ok, f"Unexpected issues: {issues}"


def test_validator_fails_on_missing_artifacts(tmp_path):
    ok, issues = Validator(output_dir=tmp_path).run()
    assert not ok
    assert any("missing artifact" in i for i in issues)


def test_validator_detects_invalid_json(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    # corrupt one artifact
    (tmp_path / "symbols.json").write_text("not valid json")
    ok, issues = Validator(output_dir=tmp_path).run()
    assert not ok
    assert any("symbols.json" in i for i in issues)


def test_validator_detects_forbidden_claim(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    bad_candidates = [{"candidate_id": "x", "claim": "proven vulnerability found"}]
    (tmp_path / "code_candidates.json").write_text(json.dumps(bad_candidates))
    ok, issues = Validator(output_dir=tmp_path).run()
    assert not ok
    assert any("proven vulnerability" in i for i in issues)


def test_full_pipeline_validates(tmp_path, update_fixture_dir, registry_path):
    """전체 파이프라인 실행 후 validate가 통과해야 한다."""
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    SecurityModelBuilder(
        dir_path=update_fixture_dir, compile_commands=None,
        registry_path=registry_path, output_dir=tmp_path,
    ).run()
    CodeMode(
        dir_path=update_fixture_dir, compile_commands=None,
        output_dir=tmp_path, llm_config=LLMConfig(),
    ).run()
    ScenarioMode(
        dir_path=update_fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="secure_update_install_integrity",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()

    ok, issues = Validator(output_dir=tmp_path).run()
    assert ok, f"Validation failed after full pipeline: {issues}"
