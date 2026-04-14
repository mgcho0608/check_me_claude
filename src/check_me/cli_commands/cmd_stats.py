"""check_me stats — 분석 결과 통계 출력."""

from __future__ import annotations

import json
from pathlib import Path

import click

from check_me.core.stats import StatsReader


@click.command()
@click.option("--dir-path", required=True, type=click.Path(exists=True),
              help="분석 대상 소스 디렉터리")
@click.option("--output-dir", default=None, type=click.Path(),
              help="아티팩트 디렉터리")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="JSON 형식으로 출력")
def stats(dir_path: str, output_dir: str | None, as_json: bool) -> None:
    """분석 아티팩트의 통계를 출력한다."""
    output_dir_ = Path(output_dir) if output_dir else Path(dir_path) / ".check_me"
    reader = StatsReader(output_dir=output_dir_)

    if as_json:
        report = reader.full_report()
        click.echo(json.dumps(report, indent=2, ensure_ascii=False))
        return

    # human-readable 출력
    summary = reader.summarize()
    click.echo(f"[stats/index] {summary}")

    report = reader.full_report()

    _print_candidate_section("code", report["code_candidates"])
    _print_candidate_section("scenario", report["scenario_candidates"])

    prim = report["primitives_summary"]
    if prim.get("available"):
        click.echo(
            f"[stats/primitives] functions={prim['function_count']}, "
            f"result_use_links={prim['result_use_links']}, "
            f"enforcement_links={prim['enforcement_links']}, "
            f"state_lifecycle={prim['state_lifecycle_entries']}"
        )

    interp = report["interpretations"]
    if interp.get("available"):
        click.echo(
            f"[stats/interpretations] total={interp['total']}, "
            f"llm_used={interp['llm_used']}, placeholder={interp['placeholder']}"
        )

    val = report["validation"]
    status = "OK" if val["ok"] else f"FAILED ({val['issue_count']} issues)"
    click.echo(f"[stats/validation] {status}")


def _print_candidate_section(mode: str, data: dict) -> None:
    if not data.get("available"):
        click.echo(f"[stats/{mode}_candidates] not available")
        return

    by_state = data.get("by_state", {})
    active = by_state.get("ACTIVE", 0)
    affected = by_state.get("SANITIZER_AFFECTED", 0)
    bounded = by_state.get("BOUNDARY_LIMITED", 0)

    click.echo(
        f"[stats/{mode}_candidates] total={data['total']}, "
        f"ACTIVE={active}, SANITIZER_AFFECTED={affected}, BOUNDARY_LIMITED={bounded}"
    )

    by_family = data.get("by_family", {})
    if by_family:
        for family, count in sorted(by_family.items(), key=lambda x: -x[1]):
            click.echo(f"  {family}: {count}")
