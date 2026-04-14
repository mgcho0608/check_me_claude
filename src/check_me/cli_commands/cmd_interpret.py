"""check_me interpret — LLM 기반 candidate 구조적 해석."""

from __future__ import annotations

import json
from pathlib import Path

import click

from check_me.config import CheckMeConfig
from check_me.llm.client import LLMClient
from check_me.llm.interpreter import CandidateInterpreter


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True),
              help="분석 대상 소스 디렉터리")
@click.option("--output-dir", default=None, type=click.Path(),
              help="아티팩트 디렉터리")
@click.option("--mode", default="both", type=click.Choice(["code", "scenario", "both"]),
              help="해석할 candidate 종류")
@click.option("--only-active", is_flag=True, default=True,
              help="ACTIVE 상태 candidate만 해석 (기본값)")
@click.option("--all-states", is_flag=True, default=False,
              help="모든 상태 candidate 해석")
def interpret(
    dir_path: str,
    output_dir: str | None,
    mode: str,
    only_active: bool,
    all_states: bool,
) -> None:
    """LLM을 사용해 보안 후보의 구조적 의미를 해석한다.

    LLM은 탐지기가 아닌 해석기다. 결과는 interpretations.json에 저장된다.
    LLM이 비활성화된 경우 placeholder 해석이 저장된다.
    """
    output_dir_ = Path(output_dir) if output_dir else Path(dir_path) / ".check_me"
    cfg = CheckMeConfig.load()
    client = LLMClient(cfg.llm)
    interpreter = CandidateInterpreter(client)

    active_only = not all_states

    if not client.is_available():
        click.echo(
            "[interpret] LLM not available — running in placeholder mode.\n"
            "  To enable: set CHECK_ME_LLM_ENABLED=true and configure .env"
        )

    all_candidates: list[dict] = []
    if mode in ("code", "both"):
        all_candidates.extend(_load_candidates(output_dir_, "code_candidates.json"))
    if mode in ("scenario", "both"):
        all_candidates.extend(_load_candidates(output_dir_, "scenario_candidates.json"))

    if not all_candidates:
        click.echo("[interpret] No candidates found. Run `check_me model` first.")
        return

    interpretations = interpreter.interpret_all(all_candidates, only_active=active_only)

    output = [
        {
            "candidate_id": i.candidate_id,
            "interpretation": i.interpretation,
            "llm_used": i.llm_used,
            "model": i.model,
        }
        for i in interpretations
    ]

    out_path = output_dir_ / "interpretations.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    active_count = sum(1 for i in interpretations if i.llm_used)
    click.echo(f"[interpret] total={len(interpretations)}, llm_used={active_count}")
    click.echo(f"[interpret] written to: {out_path}")


def _load_candidates(output_dir: Path, name: str) -> list[dict]:
    path = output_dir / name
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))
