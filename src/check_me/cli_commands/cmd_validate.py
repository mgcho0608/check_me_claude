"""check_me validate — 아티팩트 유효성 검사."""

from __future__ import annotations

from pathlib import Path

import click

from check_me.core.validator import Validator


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True), help="분석 대상 소스 디렉터리")
@click.option("--output-dir", default=None, type=click.Path(), help="아티팩트 디렉터리")
def validate(dir_path: str, output_dir: str | None) -> None:
    """생성된 아티팩트의 스키마와 일관성을 검증한다."""
    dir_path_ = Path(dir_path)
    output_dir_ = Path(output_dir) if output_dir else dir_path_ / ".check_me"

    validator = Validator(output_dir=output_dir_)
    ok, issues = validator.run()

    if ok:
        click.echo("[validate] OK — no issues found")
    else:
        click.echo(f"[validate] FAILED — {len(issues)} issue(s):")
        for issue in issues:
            click.echo(f"  - {issue}")
        raise SystemExit(1)
