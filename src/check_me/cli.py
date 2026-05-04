"""Command-line entry point.

Examples
--------
Run Step 1 over the contiki-ng dataset and write the substrate JSON to
``out/contiki-ng-CVE-2021-21281/substrate.json``::

    python -m check_me step1 \\
      --src datasets/contiki-ng-CVE-2021-21281/source \\
      --project contiki-ng \\
      --cve CVE-2021-21281 \\
      --out out/contiki-ng-CVE-2021-21281/substrate.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .step1 import runner as step1_runner


def _step1(args: argparse.Namespace) -> int:
    src = Path(args.src)
    if not src.is_dir():
        print(f"error: --src is not a directory: {src}", file=sys.stderr)
        return 2
    substrate, report = step1_runner.run(
        src,
        project_name=args.project,
        cve=args.cve,
        extra_args=tuple(args.extra_arg),
    )
    out = Path(args.out)
    step1_runner.write_substrate(substrate, out)
    print(
        f"step1: {report.files_parsed} files, "
        f"{report.parse_errors} parse errors, "
        f"{report.edges_total} call edges "
        f"(direct={report.edges_direct} indirect={report.edges_indirect}), "
        f"{report.dcf_total} dcf entries "
        f"(branch={report.dcf_branch} loop={report.dcf_loop} "
        f"def_use={report.dcf_def_use}), "
        f"{report.guards_total} guards, "
        f"{report.trust_total} trust boundaries, "
        f"{report.callbacks_total} callbacks "
        f"in {report.elapsed_sec:.1f}s -> {out}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-me")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("step1", help="Run deterministic substrate extraction")
    p1.add_argument("--src", required=True, help="project source root")
    p1.add_argument("--project", required=True, help="project name")
    p1.add_argument("--cve", required=True, help="CVE identifier")
    p1.add_argument("--out", required=True, help="output substrate.json path")
    p1.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        metavar="FLAG",
        help=(
            "Extra clang flag for fallback parsing (no compile_commands.json)."
            " Repeatable. Example: --extra-arg=-DHAVE_CONFIG_H=0"
        ),
    )
    p1.set_defaults(func=_step1)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
