"""Code Mode 테스트 — source/sink 매칭, candidate 생성."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.config import LLMConfig
from check_me.core.indexer import Indexer
from check_me.core.security_model import SecurityModelBuilder
from check_me.modes.code_mode import CodeMode


def _setup(tmp_path: Path, fixture_dir: Path, registry_path: Path) -> None:
    Indexer(dir_path=fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    SecurityModelBuilder(
        dir_path=fixture_dir,
        compile_commands=None,
        registry_path=registry_path,
        output_dir=tmp_path,
    ).run()


def test_code_mode_creates_artifacts(tmp_path, buffer_fixture_dir, registry_path):
    _setup(tmp_path, buffer_fixture_dir, registry_path)
    result = CodeMode(
        dir_path=buffer_fixture_dir,
        compile_commands=None,
        output_dir=tmp_path,
        llm_config=LLMConfig(),
    ).run()

    for name in ["source_sink_matches.json", "flow_seeds.json",
                 "propagation_paths.json", "code_candidates.json"]:
        assert (tmp_path / name).exists(), f"missing: {name}"


def test_code_candidates_valid_schema(tmp_path, buffer_fixture_dir, registry_path):
    _setup(tmp_path, buffer_fixture_dir, registry_path)
    CodeMode(
        dir_path=buffer_fixture_dir, compile_commands=None,
        output_dir=tmp_path, llm_config=LLMConfig(),
    ).run()

    candidates = json.loads((tmp_path / "code_candidates.json").read_text(encoding="utf-8"))
    for c in candidates:
        assert "candidate_id" in c
        assert "state" in c
        assert "confidence" in c
        assert "claim" in c
        # must-not-claim 검사
        claim = c["claim"].lower()
        assert "proven vulnerability" not in claim
        assert "exploitable" not in claim
        assert "execution-path verified" not in claim


def test_code_candidates_state_values(tmp_path, buffer_fixture_dir, registry_path):
    _setup(tmp_path, buffer_fixture_dir, registry_path)
    CodeMode(
        dir_path=buffer_fixture_dir, compile_commands=None,
        output_dir=tmp_path, llm_config=LLMConfig(),
    ).run()

    candidates = json.loads((tmp_path / "code_candidates.json").read_text(encoding="utf-8"))
    valid_states = {"ACTIVE", "FILTERED", "BOUNDARY_LIMITED", "SANITIZER_AFFECTED"}
    for c in candidates:
        assert c["state"] in valid_states, f"invalid state: {c['state']}"


def test_code_mode_deterministic(tmp_path, buffer_fixture_dir, registry_path):
    """동일 입력 → 동일 candidate 목록."""
    out1 = tmp_path / "r1"
    out2 = tmp_path / "r2"
    out1.mkdir(); out2.mkdir()

    for out in [out1, out2]:
        _setup(out, buffer_fixture_dir, registry_path)
        CodeMode(
            dir_path=buffer_fixture_dir, compile_commands=None,
            output_dir=out, llm_config=LLMConfig(),
        ).run()

    c1 = (out1 / "code_candidates.json").read_text(encoding="utf-8")
    c2 = (out2 / "code_candidates.json").read_text(encoding="utf-8")
    assert c1 == c2
