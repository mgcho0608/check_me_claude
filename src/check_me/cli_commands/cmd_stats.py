"""check_me stats — 분석 결과 통계 출력."""

from __future__ import annotations

from pathlib import Path

import click

from check_me.core.stats import StatsReader


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True), help="분석 대상 소스 디렉터리")
@click.option("--output-dir", default=None, type=click.Path(), help="아티팩트 디렉터리")
def stats(dir_path: str, output_dir: str | None) -> None:
    """분석 아티팩트의 통계를 출력한다."""
    dir_path_ = Path(dir_path)
    output_dir_ = Path(output_dir) if output_dir else dir_path_ / ".check_me"

    reader = StatsReader(output_dir=output_dir_)
    summary = reader.summarize()

    click.echo(f"[stats] {summary}")
