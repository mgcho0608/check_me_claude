"""LLM interpret 테스트 — LLM 비활성 시 placeholder 동작."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.config import LLMConfig
from check_me.core.indexer import Indexer
from check_me.core.security_model import SecurityModelBuilder
from check_me.llm.client import LLMClient
from check_me.llm.interpreter import CandidateInterpreter
from check_me.modes.code_mode import CodeMode
from check_me.modes.scenario_mode import ScenarioMode


def _run_full_pipeline(tmp_path, fixture_dir, registry_path):
    Indexer(dir_path=fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    SecurityModelBuilder(
        dir_path=fixture_dir, compile_commands=None,
        registry_path=registry_path, output_dir=tmp_path,
    ).run()
    CodeMode(
        dir_path=fixture_dir, compile_commands=None,
        output_dir=tmp_path, llm_config=LLMConfig(),
    ).run()
    ScenarioMode(
        dir_path=fixture_dir, compile_commands=None,
        output_dir=tmp_path, profile="secure_update_install_integrity",
        scenario_spec=None, llm_config=LLMConfig(),
    ).run()


def test_interpret_placeholder_when_llm_disabled(
    tmp_path, update_fixture_dir, registry_path
):
    _run_full_pipeline(tmp_path, update_fixture_dir, registry_path)

    candidates = json.loads(
        (tmp_path / "scenario_candidates.json").read_text(encoding="utf-8")
    )
    assert len(candidates) > 0

    cfg = LLMConfig()  # enabled=False by default
    client = LLMClient(cfg)
    interpreter = CandidateInterpreter(client)

    results = interpreter.interpret_all(candidates, only_active=False)

    assert len(results) == len(candidates)
    for r in results:
        assert r.candidate_id
        assert r.interpretation
        assert r.llm_used is False


def test_interpret_only_active(tmp_path, update_fixture_dir, registry_path):
    _run_full_pipeline(tmp_path, update_fixture_dir, registry_path)

    candidates = json.loads(
        (tmp_path / "scenario_candidates.json").read_text(encoding="utf-8")
    )
    cfg = LLMConfig()
    client = LLMClient(cfg)
    interpreter = CandidateInterpreter(client)

    results = interpreter.interpret_all(candidates, only_active=True)
    assert len(results) == len(candidates)

    # ACTIVE가 아닌 것은 "[skipped" prefix
    for r, c in zip(results, candidates):
        if c.get("state") != "ACTIVE":
            assert "[skipped" in r.interpretation


def test_interpret_output_no_forbidden_claims(
    tmp_path, update_fixture_dir, registry_path
):
    _run_full_pipeline(tmp_path, update_fixture_dir, registry_path)
    candidates = json.loads(
        (tmp_path / "scenario_candidates.json").read_text(encoding="utf-8")
    )
    cfg = LLMConfig()
    interpreter = CandidateInterpreter(LLMClient(cfg))
    results = interpreter.interpret_all(candidates, only_active=False)

    forbidden = [
        "proven vulnerability", "exploitable confirmed",
        "race detected", "timing attack confirmed",
    ]
    for r in results:
        text = r.interpretation.lower()
        for f in forbidden:
            assert f not in text, f"forbidden claim in interpretation: {f}"


def test_interpret_llm_unavailable_returns_placeholder():
    """is_available=False 시 placeholder 반환 확인."""
    client = LLMClient(LLMConfig(enabled=False))
    interpreter = CandidateInterpreter(client)

    candidates = [
        {"candidate_id": "test_001", "state": "ACTIVE",
         "confidence": "low", "claim": "structural concern",
         "evidence": {}, "family": "TEST_FAMILY"},
    ]
    results = interpreter.interpret_all(candidates, only_active=False)
    assert len(results) == 1
    assert results[0].llm_used is False
    assert "LLM disabled" in results[0].interpretation
