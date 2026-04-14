"""E2E CLI 통합 테스트 — check_me CLI 전체 워크플로우.

Click CliRunner를 사용해 subprocess 없이 CLI를 in-process로 실행한다.
이 방식은 Linux/Windows 모두 인코딩 이슈 없이 동작한다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from check_me.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent / "rules"


@pytest.fixture
def runner():
    return CliRunner()


class TestCLIBasic:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "check_me" in result.output

    def test_list_profiles(self, runner):
        result = runner.invoke(main, ["list-profiles"])
        assert result.exit_code == 0, result.output
        assert "secure_update_install_integrity" in result.output
        assert "auth_session_replay_state" in result.output
        assert "[stable]" in result.output
        assert "[experimental]" in result.output

    def test_all_subcommands_registered(self, runner):
        result = runner.invoke(main, ["--help"])
        for cmd in ["index", "security-model", "model", "stats",
                    "validate", "list-profiles", "interpret", "spec-check"]:
            assert cmd in result.output, f"subcommand not found: {cmd}"


class TestCLIIndexPipeline:
    def test_index_creates_artifacts(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        result = runner.invoke(main, [
            "index", "--dir-path", fixture, "--output-dir", str(tmp_path)
        ])
        assert result.exit_code == 0, result.output
        assert "files:" in result.output
        assert "functions:" in result.output

        for name in ["files.json", "symbols.json", "call_graph.json",
                     "function_summaries.json", "primitives.json", "stats.json"]:
            assert (tmp_path / name).exists(), f"missing: {name}"

    def test_validate_after_index(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        result = runner.invoke(main, [
            "validate", "--dir-path", fixture, "--output-dir", str(tmp_path)
        ])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_validate_fails_without_index(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        result = runner.invoke(main, [
            "validate", "--dir-path", fixture, "--output-dir", str(tmp_path)
        ])
        assert result.exit_code != 0

    def test_stats_after_index(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        result = runner.invoke(main, [
            "stats", "--dir-path", fixture, "--output-dir", str(tmp_path)
        ])
        assert result.exit_code == 0, result.output
        assert "file_count" in result.output

    def test_stats_json_output(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        result = runner.invoke(main, [
            "stats", "--dir-path", fixture, "--output-dir", str(tmp_path), "--json"
        ])
        assert result.exit_code == 0
        report = json.loads(result.output)
        assert "index" in report
        assert "validation" in report


class TestCLIModelPipeline:
    def _setup(self, runner, tmp_path: Path, fixture: str) -> None:
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])
        runner.invoke(main, [
            "security-model",
            "--dir-path", fixture,
            "--registry-path", str(RULES_DIR / "c_cpp_registry.yaml"),
            "--output-dir", str(tmp_path),
        ])

    def test_code_mode(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "buffer_safety")
        self._setup(runner, tmp_path, fixture)

        result = runner.invoke(main, [
            "model", "--mode", "code",
            "--dir-path", fixture,
            "--output-dir", str(tmp_path),
        ])
        assert result.exit_code == 0, result.output
        assert "candidates:" in result.output
        assert (tmp_path / "code_candidates.json").exists()

    def test_scenario_mode(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        self._setup(runner, tmp_path, fixture)

        result = runner.invoke(main, [
            "model", "--mode", "scenario",
            "--dir-path", fixture,
            "--profile", "secure_update_install_integrity",
            "--output-dir", str(tmp_path),
        ])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "scenario_candidates.json").exists()
        assert (tmp_path / "profile_summary.json").exists()

    def test_scenario_mode_requires_profile_or_spec(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        self._setup(runner, tmp_path, fixture)

        result = runner.invoke(main, [
            "model", "--mode", "scenario",
            "--dir-path", fixture,
            "--output-dir", str(tmp_path),
        ])
        assert result.exit_code != 0

    def test_code_candidates_valid_after_cli(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "buffer_safety")
        self._setup(runner, tmp_path, fixture)
        runner.invoke(main, [
            "model", "--mode", "code",
            "--dir-path", fixture, "--output-dir", str(tmp_path),
        ])

        candidates = json.loads(
            (tmp_path / "code_candidates.json").read_text(encoding="utf-8")
        )
        valid_states = {"ACTIVE", "SANITIZER_AFFECTED", "BOUNDARY_LIMITED", "FILTERED"}
        for c in candidates:
            assert c["state"] in valid_states
            assert "proven" not in c["claim"].lower()

    def test_stats_after_full_pipeline(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        self._setup(runner, tmp_path, fixture)
        runner.invoke(main, [
            "model", "--mode", "scenario",
            "--dir-path", fixture,
            "--profile", "secure_update_install_integrity",
            "--output-dir", str(tmp_path),
        ])

        result = runner.invoke(main, [
            "stats", "--dir-path", fixture, "--output-dir", str(tmp_path)
        ])
        assert result.exit_code == 0
        assert "scenario_candidates" in result.output


class TestCLIInterpret:
    def _setup_with_model(self, runner, tmp_path: Path, fixture: str) -> None:
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])
        runner.invoke(main, [
            "security-model", "--dir-path", fixture,
            "--registry-path", str(RULES_DIR / "c_cpp_registry.yaml"),
            "--output-dir", str(tmp_path),
        ])
        runner.invoke(main, [
            "model", "--mode", "scenario",
            "--dir-path", fixture,
            "--profile", "secure_update_install_integrity",
            "--output-dir", str(tmp_path),
        ])

    def test_interpret_placeholder_mode(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        self._setup_with_model(runner, tmp_path, fixture)

        result = runner.invoke(main, [
            "interpret",
            "--dir-path", fixture,
            "--output-dir", str(tmp_path),
            "--mode", "scenario",
        ])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "interpretations.json").exists()

        interps = json.loads(
            (tmp_path / "interpretations.json").read_text(encoding="utf-8")
        )
        assert len(interps) > 0
        for i in interps:
            assert "candidate_id" in i
            assert "interpretation" in i
            assert "llm_used" in i
            assert i["llm_used"] is False  # LLM not configured

    def test_interpret_no_candidates_warns(self, runner, tmp_path):
        fixture = str(FIXTURES_DIR / "update_integrity")
        # index만 하고 model은 실행 안 함
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        result = runner.invoke(main, [
            "interpret", "--dir-path", fixture,
            "--output-dir", str(tmp_path), "--mode", "scenario",
        ])
        assert result.exit_code == 0
        assert "No candidates" in result.output


class TestCLISpecCheck:
    def test_valid_spec(self, runner, tmp_path):
        spec = {
            "name": "e2e_test_spec",
            "description": "E2E test scenario spec",
            "candidate_families": ["RESULT_NOT_ENFORCED"],
        }
        spec_path = tmp_path / "spec.yaml"
        spec_path.write_text(yaml.dump(spec), encoding="utf-8")

        result = runner.invoke(main, ["spec-check", "--scenario-spec", str(spec_path)])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_invalid_spec_missing_fields(self, runner, tmp_path):
        spec = {"description": "missing name and families"}
        spec_path = tmp_path / "bad.yaml"
        spec_path.write_text(yaml.dump(spec), encoding="utf-8")

        result = runner.invoke(main, ["spec-check", "--scenario-spec", str(spec_path)])
        assert result.exit_code != 0
        assert "FAILED" in result.output

    def test_unknown_family_rejected(self, runner, tmp_path):
        spec = {
            "name": "test", "description": "test",
            "candidate_families": ["NOT_A_REAL_FAMILY"],
        }
        spec_path = tmp_path / "spec.yaml"
        spec_path.write_text(yaml.dump(spec), encoding="utf-8")

        result = runner.invoke(main, ["spec-check", "--scenario-spec", str(spec_path)])
        assert result.exit_code != 0
        assert "unknown" in result.output


class TestCLIFullWorkflow:
    """전체 워크플로우 일관성 검사."""

    def test_validate_consistent_with_stats(self, runner, tmp_path):
        """validate OK면 stats --json의 validation도 OK여야 한다."""
        fixture = str(FIXTURES_DIR / "update_integrity")
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        val = runner.invoke(main, ["validate", "--dir-path", fixture, "--output-dir", str(tmp_path)])
        stats = runner.invoke(main, ["stats", "--dir-path", fixture, "--output-dir", str(tmp_path), "--json"])

        assert val.exit_code == 0
        report = json.loads(stats.output)
        assert report["validation"]["ok"] is True

    def test_stats_does_not_modify_artifacts(self, runner, tmp_path):
        """stats 호출이 아티팩트를 수정하지 않아야 한다."""
        fixture = str(FIXTURES_DIR / "update_integrity")
        runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(tmp_path)])

        before = {
            name: (tmp_path / name).read_text(encoding="utf-8")
            for name in ["files.json", "symbols.json", "stats.json"]
        }
        runner.invoke(main, ["stats", "--dir-path", fixture, "--output-dir", str(tmp_path)])
        after = {
            name: (tmp_path / name).read_text(encoding="utf-8")
            for name in ["files.json", "symbols.json", "stats.json"]
        }
        assert before == after

    def test_full_pipeline_deterministic(self, runner, tmp_path):
        """동일 입력에 대해 전체 파이프라인이 동일 결과를 생성한다."""
        fixture = str(FIXTURES_DIR / "update_integrity")
        registry = str(RULES_DIR / "c_cpp_registry.yaml")

        def run_pipeline(out: Path) -> None:
            runner.invoke(main, ["index", "--dir-path", fixture, "--output-dir", str(out)])
            runner.invoke(main, [
                "security-model", "--dir-path", fixture,
                "--registry-path", registry, "--output-dir", str(out),
            ])
            runner.invoke(main, [
                "model", "--mode", "scenario",
                "--dir-path", fixture,
                "--profile", "secure_update_install_integrity",
                "--output-dir", str(out),
            ])

        out1 = tmp_path / "r1"; out1.mkdir()
        out2 = tmp_path / "r2"; out2.mkdir()
        run_pipeline(out1)
        run_pipeline(out2)

        for name in ["scenario_candidates.json", "guard_evidence.json", "profile_summary.json"]:
            t1 = (out1 / name).read_text(encoding="utf-8")
            t2 = (out2 / name).read_text(encoding="utf-8")
            assert t1 == t2, f"{name} not deterministic"
