"""Scenario Mode 테스트 — profile 기반 후보 생성 및 guard evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.config import LLMConfig
from check_me.core.indexer import Indexer
from check_me.modes.scenario_mode import ScenarioMode


def _setup_index(tmp_path: Path, fixture_dir: Path) -> None:
    Indexer(dir_path=fixture_dir, compile_commands=None, output_dir=tmp_path).run()


def test_scenario_mode_update_profile(tmp_path, update_fixture_dir):
    _setup_index(tmp_path, update_fixture_dir)
    result = ScenarioMode(
        dir_path=update_fixture_dir,
        compile_commands=None,
        output_dir=tmp_path,
        profile="secure_update_install_integrity",
        scenario_spec=None,
        llm_config=LLMConfig(),
    ).run()

    assert (tmp_path / "scenario_candidates.json").exists()
    assert (tmp_path / "guard_evidence.json").exists()
    assert (tmp_path / "profile_summary.json").exists()


def test_scenario_candidates_schema(tmp_path, update_fixture_dir):
    _setup_index(tmp_path, update_fixture_dir)
    ScenarioMode(
        dir_path=update_fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="secure_update_install_integrity",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()

    candidates = json.loads((tmp_path / "scenario_candidates.json").read_text(encoding="utf-8"))
    for c in candidates:
        assert "candidate_id" in c
        assert "family" in c
        assert "state" in c
        assert "evidence" in c
        assert "confidence" in c
        assert "claim" in c
        # must-not-claim
        claim = c["claim"].lower()
        assert "proven" not in claim
        assert "exploitable" not in claim
        assert "execution-path verified" not in claim


def test_scenario_profile_summary(tmp_path, update_fixture_dir):
    _setup_index(tmp_path, update_fixture_dir)
    ScenarioMode(
        dir_path=update_fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="secure_update_install_integrity",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()

    summary = json.loads((tmp_path / "profile_summary.json").read_text(encoding="utf-8"))
    assert summary["profile_id"] == "secure_update_install_integrity"
    assert summary["maturity"] == "stable"
    assert "enabled_families" in summary
    assert "candidate_count" in summary


def test_scenario_auth_profile(tmp_path, auth_fixture_dir):
    _setup_index(tmp_path, auth_fixture_dir)
    result = ScenarioMode(
        dir_path=auth_fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="auth_session_replay_state",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()

    candidates = json.loads((tmp_path / "scenario_candidates.json").read_text(encoding="utf-8"))
    families = {c["family"] for c in candidates}
    # auth fixture에 privileged action 함수들이 있으므로 candidate가 생성돼야 함
    assert len(candidates) > 0


def test_scenario_unknown_profile_raises(tmp_path, update_fixture_dir):
    _setup_index(tmp_path, update_fixture_dir)
    with pytest.raises(ValueError, match="Unknown profile"):
        ScenarioMode(
            dir_path=update_fixture_dir, compile_commands=None,
            output_dir=tmp_path, profile="nonexistent_profile",
            scenario_spec=None, llm_config=LLMConfig(),
        ).run()


def test_scenario_deterministic(tmp_path, update_fixture_dir):
    out1 = tmp_path / "r1"
    out2 = tmp_path / "r2"
    out1.mkdir(); out2.mkdir()

    for out in [out1, out2]:
        _setup_index(out, update_fixture_dir)
        ScenarioMode(
            dir_path=update_fixture_dir, compile_commands=None,
            output_dir=out, profile="secure_update_install_integrity",
            scenario_spec=None, llm_config=LLMConfig(),
        ).run()

    c1 = (out1 / "scenario_candidates.json").read_text(encoding="utf-8")
    c2 = (out2 / "scenario_candidates.json").read_text(encoding="utf-8")
    assert c1 == c2


def test_guard_evidence_schema(tmp_path, update_fixture_dir):
    _setup_index(tmp_path, update_fixture_dir)
    ScenarioMode(
        dir_path=update_fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="secure_update_install_integrity",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()

    evidence = json.loads((tmp_path / "guard_evidence.json").read_text(encoding="utf-8"))
    for e in evidence:
        assert "function_id" in e
        assert "name" in e
        assert "file" in e
        assert "line" in e
        assert "direct_callees" in e
