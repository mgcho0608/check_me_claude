"""check_me model — Code Mode 또는 Scenario Mode 실행."""

from __future__ import annotations

from pathlib import Path

import click

from check_me.config import CheckMeConfig


@click.command()
@click.option("--mode", required=True, type=click.Choice(["code", "scenario"]), help="실행 모드")
@click.option("--dir-path", required=True, type=click.Path(exists=True), help="분석 대상 소스 디렉터리")
@click.option("--compile-commands", default=None, type=click.Path(), help="compile_commands.json 경로")
@click.option("--profile", default=None, help="Scenario Mode 도메인 프로필 ID")
@click.option("--scenario-spec", default=None, type=click.Path(), help="커스텀 시나리오 스펙 YAML 경로")
@click.option("--output-dir", default=None, type=click.Path(), help="아티팩트 출력 디렉터리")
def model(
    mode: str,
    dir_path: str,
    compile_commands: str | None,
    profile: str | None,
    scenario_spec: str | None,
    output_dir: str | None,
) -> None:
    """Code Mode 또는 Scenario Mode로 보안 후보를 생성한다."""
    dir_path_ = Path(dir_path)
    output_dir_ = Path(output_dir) if output_dir else dir_path_ / ".check_me"
    compile_commands_ = Path(compile_commands) if compile_commands else None
    output_dir_.mkdir(parents=True, exist_ok=True)

    cfg = CheckMeConfig.load()

    if mode == "code":
        from check_me.modes.code_mode import CodeMode
        runner = CodeMode(
            dir_path=dir_path_,
            compile_commands=compile_commands_,
            output_dir=output_dir_,
            llm_config=cfg.llm,
        )
    else:
        if profile is None and scenario_spec is None:
            raise click.UsageError("scenario mode는 --profile 또는 --scenario-spec 중 하나가 필요합니다.")
        from check_me.modes.scenario_mode import ScenarioMode
        runner = ScenarioMode(
            dir_path=dir_path_,
            compile_commands=compile_commands_,
            output_dir=output_dir_,
            profile=profile,
            scenario_spec=Path(scenario_spec) if scenario_spec else None,
            llm_config=cfg.llm,
        )

    result = runner.run()
    click.echo(f"[model/{mode}] candidates: {result.candidate_count}")
    click.echo(f"[model/{mode}] artifacts written to: {output_dir_}")
