"""
check_me CLI 진입점.
모든 공식 기능은 이 CLI를 통해서만 접근한다.
"""

from __future__ import annotations

import click

from check_me.cli_commands import (
    cmd_index,
    cmd_list_profiles,
    cmd_model,
    cmd_security_model,
    cmd_stats,
    cmd_validate,
)


@click.group()
@click.version_option(version="0.1.0", prog_name="check_me")
def main() -> None:
    """check_me - C/C++-first deterministic static security candidate generator."""


main.add_command(cmd_index.index)
main.add_command(cmd_security_model.security_model, name="security-model")
main.add_command(cmd_model.model)
main.add_command(cmd_stats.stats)
main.add_command(cmd_validate.validate)
main.add_command(cmd_list_profiles.list_profiles, name="list-profiles")
