"""check_me security-model — 보안 모델(규칙 레지스트리) 기반 분석 기반 생성."""

from __future__ import annotations

from pathlib import Path

import click

from check_me.core.security_model import SecurityModelBuilder


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True), help="분석 대상 소스 디렉터리")
@click.option("--compile-commands", default=None, type=click.Path(), help="compile_commands.json 경로")
@click.option("--registry-path", required=True, type=click.Path(exists=True), help="규칙 레지스트리 YAML 경로")
@click.option("--output-dir", default=None, type=click.Path(), help="아티팩트 출력 디렉터리")
def security_model(
    dir_path: str,
    compile_commands: str | None,
    registry_path: str,
    output_dir: str | None,
) -> None:
    """규칙 레지스트리를 기반으로 보안 모델 아티팩트를 생성한다."""
    dir_path_ = Path(dir_path)
    output_dir_ = Path(output_dir) if output_dir else dir_path_ / ".check_me"
    compile_commands_ = Path(compile_commands) if compile_commands else None

    output_dir_.mkdir(parents=True, exist_ok=True)

    builder = SecurityModelBuilder(
        dir_path=dir_path_,
        compile_commands=compile_commands_,
        registry_path=Path(registry_path),
        output_dir=output_dir_,
    )
    result = builder.run()

    click.echo(f"[security-model] rules loaded: {result.rule_count}")
    click.echo(f"[security-model] artifacts written to: {output_dir_}")
