"""Command-line entry point.

Two subcommands:

- ``step1`` — run the deterministic substrate extractor over a
  project source tree and write a substrate JSON document.
- ``regex-compare`` — run both the Clang AST call_graph extractor
  and the naive regex baseline on the same tree and print a
  comparison report (Stage 0 exit criterion 1).

Both subcommands take ``--src`` (project root), ``--project``,
``--cve``, and a repeatable ``--extra-arg`` flag for clang
arguments injected when no ``compile_commands.json`` is
available.

Example::

    python -m check_me step1 \\
      --src datasets/<project>-<cve>/source \\
      --project <project> --cve <CVE-id> \\
      --out out/<project>-<cve>/substrate.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .step1 import call_graph as cg_mod
from .step1 import regex_baseline as regex_mod
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
        f"{report.callbacks_total} callbacks, "
        f"{report.config_total} config triggers, "
        f"{report.anchors_total} anchors "
        f"in {report.elapsed_sec:.1f}s -> {out}"
    )
    return 0


def _regex_compare(args: argparse.Namespace) -> int:
    """Run the Clang AST call_graph extractor and the regex baseline
    on the same project, then print a comparison report.

    Closes PLAN.md §5 Stage 0 exit criterion 1, which (per the
    measurement in ``out/STAGE0_REGEX_BASELINE_METRICS.md``) is
    phrased "Clang call graph emits an indirect-edge class regex
    cannot represent, and is free of preprocessor-disabled-code
    false positives" — the architectural advantage is precision +
    indirect-edge coverage, not raw edge count.
    """
    src = Path(args.src)
    if not src.is_dir():
        print(f"error: --src is not a directory: {src}", file=sys.stderr)
        return 2

    # 1. Clang extractor — reuse step1 runner, take only call_graph.
    substrate, clang_report = step1_runner.run(
        src,
        project_name=args.project,
        cve=args.cve,
        extra_args=tuple(args.extra_arg),
    )
    clang_edges = [
        cg_mod.CallEdge(
            caller=r["caller"],
            callee=r["callee"],
            file=r["file"],
            line=r["line"],
            kind=r["kind"],
        )
        for r in substrate["categories"]["call_graph"]
    ]

    # 2. Regex baseline.
    regex_edges = regex_mod.extract_regex_call_edges_for_project(src)

    # 3. Compare.
    cmp = regex_mod.compare_edges(clang_edges, regex_edges)

    out = Path(args.out) if args.out else None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        # Persist machine-readable comparison JSON.
        out.write_text(
            json.dumps(
                {
                    "project": args.project,
                    "cve": args.cve,
                    "comparison": cmp.to_json(),
                    "clang_kind_breakdown": {
                        "direct": clang_report.edges_direct,
                        "indirect": clang_report.edges_indirect,
                    },
                },
                indent=2,
            )
            + "\n"
        )

    direct_clang = clang_report.edges_direct
    indirect_clang = clang_report.edges_indirect
    print(
        f"clang   : {clang_report.edges_total} edges "
        f"(direct={direct_clang} indirect={indirect_clang})"
    )
    print(f"regex   : {cmp.regex_total} edges (direct only by construction)")
    print(
        f"strict-match (caller,callee,file,line): "
        f"{cmp.strict_match}"
    )
    print(
        f"fuzzy-match (caller,callee,file)       : "
        f"{cmp.fuzzy_match}"
    )
    print(
        f"clang-only (strict): {cmp.clang_total - cmp.strict_match} "
        f"-> includes {indirect_clang} indirect edges regex cannot resolve"
    )
    print(
        f"regex-only (strict): {cmp.regex_total - cmp.strict_match} "
        f"-> false positives in #ifdef-disabled blocks, etc."
    )
    if out:
        print(f"-> {out}")
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

    p2 = sub.add_parser(
        "regex-compare",
        help=(
            "Run the Clang AST call_graph extractor and the regex"
            " baseline on the same project; print metrics. Closes"
            " PLAN.md §5 Stage 0 exit criterion 1."
        ),
    )
    p2.add_argument("--src", required=True, help="project source root")
    p2.add_argument("--project", required=True, help="project name")
    p2.add_argument("--cve", required=True, help="CVE identifier")
    p2.add_argument(
        "--out",
        required=False,
        help=(
            "Optional output path for the comparison JSON. If omitted,"
            " only stdout is produced."
        ),
    )
    p2.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        metavar="FLAG",
        help="Extra clang flag for fallback parsing. Repeatable.",
    )
    p2.set_defaults(func=_regex_compare)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
