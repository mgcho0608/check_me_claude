"""check_me list-profiles — 사용 가능한 도메인 프로필 목록 출력."""

from __future__ import annotations

import click

from check_me.profiles.registry import ProfileRegistry


@click.command()
def list_profiles() -> None:
    """사용 가능한 도메인 프로필 목록을 출력한다."""
    registry = ProfileRegistry()
    profiles = registry.all()

    click.echo("Available profiles:")
    click.echo("")

    stable = [p for p in profiles if p.maturity == "stable"]
    experimental = [p for p in profiles if p.maturity == "experimental"]

    click.echo("  [stable]")
    for p in stable:
        click.echo(f"    {p.profile_id:<45} {p.description}")

    click.echo("")
    click.echo("  [experimental]")
    for p in experimental:
        click.echo(f"    {p.profile_id:<45} {p.description}")
