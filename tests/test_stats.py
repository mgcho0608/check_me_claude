"""Stats 테스트 — candidate 분포 요약, full report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.config import LLMConfig
from check_me.core.indexer import Indexer
from check_me.core.security_model import SecurityModelBuilder
from check_me.core.stats import StatsReader
from check_me.modes.code_mode import CodeMode
from check_me.modes.scenario_mode import ScenarioMode


def _full_pipeline(tmp_path, fixture_dir, registry_path):
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


def test_stats_summarize_after_index(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    reader = StatsReader(output_dir=tmp_path)
    summary = reader.summarize()
    assert "file_count" in summary
    assert "function_count" in summary


def test_stats_no_artifacts(tmp_path):
    reader = StatsReader(output_dir=tmp_path)
    summary = reader.summarize()
    assert "not found" in summary


def test_full_report_structure(tmp_path, update_fixture_dir, registry_path):
    _full_pipeline(tmp_path, update_fixture_dir, registry_path)
    reader = StatsReader(output_dir=tmp_path)
    report = reader.full_report()

    assert "index" in report
    assert "code_candidates" in report
    assert "scenario_candidates" in report
    assert "primitives_summary" in report
    assert "validation" in report


def test_full_report_candidate_counts(tmp_path, update_fixture_dir, registry_path):
    _full_pipeline(tmp_path, update_fixture_dir, registry_path)
    reader = StatsReader(output_dir=tmp_path)
    report = reader.full_report()

    sc = report["scenario_candidates"]
    assert sc["available"] is True
    assert sc["total"] > 0
    assert "by_state" in sc
    assert "by_family" in sc
    assert "by_confidence" in sc


def test_full_report_primitives(tmp_path, update_fixture_dir, registry_path):
    _full_pipeline(tmp_path, update_fixture_dir, registry_path)
    reader = StatsReader(output_dir=tmp_path)
    report = reader.full_report()

    prim = report["primitives_summary"]
    assert prim["available"] is True
    assert prim["function_count"] > 0
    assert "result_use_links" in prim
    assert "enforcement_links" in prim


def test_full_report_validation_ok(tmp_path, update_fixture_dir, registry_path):
    _full_pipeline(tmp_path, update_fixture_dir, registry_path)
    reader = StatsReader(output_dir=tmp_path)
    report = reader.full_report()

    val = report["validation"]
    assert val["ok"] is True
    assert val["issue_count"] == 0


def test_candidate_state_values_valid(tmp_path, update_fixture_dir, registry_path):
    """by_state 딕셔너리의 모든 키가 유효한 state여야 한다."""
    _full_pipeline(tmp_path, update_fixture_dir, registry_path)
    reader = StatsReader(output_dir=tmp_path)
    report = reader.full_report()

    valid_states = {"ACTIVE", "SANITIZER_AFFECTED", "BOUNDARY_LIMITED", "FILTERED"}
    for mode in ("code_candidates", "scenario_candidates"):
        section = report[mode]
        if section.get("available"):
            for state in section["by_state"]:
                assert state in valid_states, f"invalid state in {mode}: {state}"
