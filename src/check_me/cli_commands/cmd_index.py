"""check_me index — 소스 트리 인덱싱 및 공유 아티팩트 생성."""

from __future__ import annotations

from pathlib import Path

import click

from check_me.core.indexer import Indexer


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True), help="분석 대상 소스 디렉터리")
@click.option("--compile-commands", default=None, type=click.Path(), help="compile_commands.json 경로")
@click.option("--output-dir", default=None, type=click.Path(), help="아티팩트 출력 디렉터리 (기본: --dir-path/.check_me)")
def index(dir_path: str, compile_commands: str | None, output_dir: str | None) -> None:
    """소스 트리를 인덱싱하고 shared 아티팩트를 생성한다."""
    dir_path_ = Path(dir_path)
    output_dir_ = Path(output_dir) if output_dir else dir_path_ / ".check_me"
    compile_commands_ = Path(compile_commands) if compile_commands else None

    output_dir_.mkdir(parents=True, exist_ok=True)

    indexer = Indexer(
        dir_path=dir_path_,
        compile_commands=compile_commands_,
        output_dir=output_dir_,
    )
    result = indexer.run()

    click.echo(f"[index] files: {result.file_count}, functions: {result.function_count}")
    click.echo(f"[index] artifacts written to: {output_dir_}")
