"""Command-line entry point.

Subcommands cover all four pipeline steps plus the gold-vs-output
evaluator:

- ``step1`` — deterministic substrate extraction from a project
  source tree.
- ``regex-compare`` — Clang vs regex baseline diagnostic (Stage 0
  exit criterion 1).
- ``step2`` — LLM entrypoint mining + verification over a Step 1
  substrate.
- ``step3`` — LLM Evidence IR synthesis over Step 1 substrate +
  Step 2 entrypoints + project source.
- ``step4`` — LLM attack scenario synthesis over Step 3 IRs +
  project source.
- ``eval`` — gold-vs-output matching across all four steps for
  one dataset; writes ``eval_report.json`` per PLAN §5 Stage 3
  exit criteria.

LLM-using subcommands (``step2`` / ``step3`` / ``step4`` /
``eval``) read ``CHECK_ME_LLM_*`` env vars (see
``docs/LLM_CONFIG.md``).

Examples (replace ``<key>`` with a dataset directory name such
as ``<project>-<CVE>``, e.g. one of the entries under
``datasets/``):

    # Stage 0
    python -m check_me step1 \\
      --src datasets/<key>/source \\
      --project <project> --cve <CVE> \\
      --out out/<key>/substrate.json

    # Stage 1 — pass --source so the verifier can read source code
    python -m check_me step2 \\
      --substrate out/<key>/substrate.json \\
      --source datasets/<key>/source \\
      --out out/<key>/entrypoints.json

    # Stage 2
    python -m check_me step3 \\
      --substrate out/<key>/substrate.json \\
      --entrypoints out/<key>/entrypoints.json \\
      --source datasets/<key>/source \\
      --out out/<key>/evidence_irs.json
    python -m check_me step4 \\
      --evidence-irs out/<key>/evidence_irs.json \\
      --source datasets/<key>/source \\
      --out out/<key>/attack_scenarios.json

    # Stage 3
    python -m check_me eval \\
      --gold datasets/<key>/gold \\
      --out-dir out/<key> \\
      --report out/<key>/eval_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .step1 import call_graph as cg_mod
from .step1 import regex_baseline as regex_mod
from .step1 import runner as step1_runner
from .step2 import runner as step2_runner
from .step3 import runner as step3_runner
from .step4 import runner as step4_runner
from .eval import runner as eval_runner


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
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help=(
            "Stream INFO-level progress logs to stderr. Pass twice"
            " (-vv) for DEBUG. Without this flag the runners are silent"
            " until each subcommand's final summary line — useful in CI"
            " but unhelpful when watching a long Step 2 / Step 3 / Step 4"
            " run for liveness. Adds per-candidate / per-IR / per-chunk"
            " progress lines so you can `tail -f` a log file or follow"
            " stderr in real time."
        ),
    )
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

    p3 = sub.add_parser(
        "step2",
        help=(
            "Run Step 2 (LLM entrypoint mining + verification) over a"
            " Step 1 substrate JSON. Reads CHECK_ME_LLM_* from env or .env."
        ),
    )
    p3.add_argument("--substrate", required=True, help="path to a step1 substrate JSON")
    p3.add_argument("--out", required=True, help="output path for entrypoints.json")
    p3.add_argument(
        "--source",
        required=False,
        default=None,
        help=(
            "Project source root (matches step1 --src). When supplied,"
            " the Step 2 verifier sees source excerpts of the candidate"
            " function and its 2-hop call-graph neighbourhood, in"
            " addition to the substrate slice — this is the source-"
            " visibility upgrade that lets Step 2 recover entrypoints"
            " whose substrate evidence is sparse (e.g. library export"
            " APIs not registered as callbacks). Without --source the"
            " verifier runs in substrate-only mode (legacy behaviour)."
        ),
    )
    p3.add_argument(
        "--no-chunk-focused-slice",
        action="store_true",
        help=(
            "Disable per-chunk substrate-slice projection. By default the"
            " chunked miner projects the full slice down to the chunk's"
            " 2-hop neighbourhood (preserves Part B vocabulary —"
            " callback_registrations / trust_boundaries / indirect call"
            " edges from chunk candidates / config_triggers — and scopes"
            " the bulk: direct call edges, guards, evidence_anchors)."
            " The escape hatch reverts to the un-projected behaviour for"
            " projects where Part A reasoning needs more cross-cutting"
            " context than the 2-hop neighbourhood provides — see"
            " PLAN.md Appendix A 'Known risk: chunk slice scoping'."
        ),
    )
    p3.add_argument(
        "--chunk-hop-depth",
        type=int,
        default=1,
        help=(
            "Hop depth for the per-chunk substrate-slice projection"
            " (default: 1). The miner proposes per-candidate rows"
            " from direct 1-hop neighbourhood evidence; deeper chain"
            " validation is the verifier's job (per-candidate hop=2"
            " plus source excerpts). Bump to 2+ on projects whose"
            " miner reasoning needs more cross-cutting context, at"
            " the cost of more tokens per chunk — risks context-"
            " window overflow on well-connected codebases."
        ),
    )
    p3.set_defaults(func=_step2)

    p4 = sub.add_parser(
        "step3",
        help=(
            "Run Step 3 (LLM Evidence IR synthesis) over Step 1 substrate"
            " + Step 2 entrypoints + project source. Reads CHECK_ME_LLM_*"
            " from env or .env."
        ),
    )
    p4.add_argument("--substrate", required=True, help="path to a step1 substrate JSON")
    p4.add_argument("--entrypoints", required=True, help="path to a step2 entrypoints JSON")
    p4.add_argument("--source", required=True, help="project source root (matches step1 --src)")
    p4.add_argument("--out", required=True, help="output path for evidence_irs.json")
    p4.add_argument(
        "--include-quarantined",
        action="store_true",
        help=(
            "Also synthesise IRs for quarantined entrypoints (default: kept-only)."
            " Use for audit / recall dips."
        ),
    )
    p4.add_argument(
        "--no-escalation",
        action="store_true",
        help=(
            "Disable the N=2→N=3 escalation pass. By default, when the"
            " per-IR LLM sets needs_more_context: true, the runner"
            " recomputes the neighborhood at deeper hops and re-issues"
            " the synthesis call."
        ),
    )
    p4.add_argument(
        "--escalation-hop-depth",
        type=int,
        default=3,
        help=(
            "Hop depth used when escalating an IR that requested more"
            " context (default: 3, i.e. N=2 → N=3)."
        ),
    )
    p4.set_defaults(func=_step3)

    p5 = sub.add_parser(
        "step4",
        help=(
            "Run Step 4 (LLM attack scenario synthesis) over Step 3 IRs +"
            " project source. Reads CHECK_ME_LLM_* from env or .env."
        ),
    )
    p5.add_argument("--evidence-irs", required=True, help="path to a step3 evidence_irs JSON")
    p5.add_argument("--source", required=True, help="project source root")
    p5.add_argument("--out", required=True, help="output path for attack_scenarios.json")
    p5.add_argument(
        "--synth-chunk-size",
        type=int,
        default=step4_runner.synth_mod.DEFAULT_CHUNK_SIZE,
        help=(
            "Sink-bearing IRs per chunked Step 4 call (default: 15)."
            " Single-call mode is used when sink-bearing IR count <="
            " this. Set to 0 to force single-call regardless of size."
        ),
    )
    p5.add_argument(
        "--synth-max-workers",
        type=int,
        default=step4_runner.synth_mod.DEFAULT_MAX_WORKERS,
        help=(
            "Concurrent chunked-Step-4 LLM calls (default: 1, i.e."
            " sequential). Raise when provider per-minute quotas allow."
        ),
    )
    p5.set_defaults(func=_step4)

    p6 = sub.add_parser(
        "eval",
        help=(
            "Match gold vs pipeline outputs across all 4 steps for one"
            " dataset; write eval_report.json. Step 3 + Step 4 use the"
            " LLM judge (CHECK_ME_LLM_*); Step 1 + Step 2 are deterministic."
        ),
    )
    p6.add_argument("--gold", required=True, help="datasets/<key>/gold directory")
    p6.add_argument("--out-dir", required=True, help="out/<key> directory with pipeline outputs")
    p6.add_argument(
        "--report",
        required=False,
        help="optional path for eval_report.json (defaults to <out-dir>/eval_report.json on success)",
    )
    p6.add_argument(
        "--skip-step3",
        action="store_true",
        help="skip the LLM-judge pass over Step 3 IRs (faster sanity check)",
    )
    p6.add_argument(
        "--skip-step4",
        action="store_true",
        help="skip the LLM-judge pass over Step 4 scenarios",
    )
    p6.set_defaults(func=_eval)

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    return args.func(args)


def _configure_logging(verbosity: int) -> None:
    """Wire up stderr logging when -v/--verbose is set.

    Without this, the runners' ``logger.info`` calls (per-candidate
    verifier progress, per-IR Step 3 progress, per-chunk Step 4
    progress) are silently dropped at Python's default WARNING
    threshold — which is exactly the case where the operator most
    needs liveness signal. Single ``-v`` switches to INFO; ``-vv``
    to DEBUG. We log to stderr so subcommands' stdout (still the
    one-line summary) stays clean for piping."""
    if verbosity <= 0:
        return
    import logging
    level = logging.INFO if verbosity == 1 else logging.DEBUG
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root = logging.getLogger()
    root.setLevel(level)
    # Avoid double-handlers on repeated invocations from tests.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)


def _step2(args: argparse.Namespace) -> int:
    substrate_path = Path(args.substrate)
    if not substrate_path.is_file():
        print(f"error: --substrate not found: {substrate_path}", file=sys.stderr)
        return 2
    source_root: Path | None = None
    if args.source:
        source_root = Path(args.source)
        if not source_root.is_dir():
            print(f"error: --source is not a directory: {source_root}", file=sys.stderr)
            return 2
    substrate = json.loads(substrate_path.read_text())
    output, report = step2_runner.run(
        substrate,
        source_root=source_root,
        miner_use_chunk_focused_slice=not args.no_chunk_focused_slice,
        miner_chunk_hop_depth=args.chunk_hop_depth,
    )
    out_path = Path(args.out)
    step2_runner.write_entrypoints(output, out_path)
    print(
        f"step2: project={report.project!r} cve={report.cve!r}"
        f" slice={report.slice_counts}"
        f" proposed={report.candidates_proposed}"
        f" kept={report.kept} quarantined={report.quarantined}"
        f" elapsed={report.elapsed_sec:.1f}s -> {out_path}"
    )
    return 0


def _step3(args: argparse.Namespace) -> int:
    substrate_path = Path(args.substrate)
    entrypoints_path = Path(args.entrypoints)
    source_root = Path(args.source)
    out_path = Path(args.out)
    for label, p in (
        ("--substrate", substrate_path),
        ("--entrypoints", entrypoints_path),
    ):
        if not p.is_file():
            print(f"error: {label} not found: {p}", file=sys.stderr)
            return 2
    if not source_root.is_dir():
        print(f"error: --source is not a directory: {source_root}", file=sys.stderr)
        return 2
    output, report = step3_runner.run(
        substrate_path=substrate_path,
        entrypoints_path=entrypoints_path,
        source_root=source_root,
        out_path=out_path,
        include_quarantined=args.include_quarantined,
        enable_escalation=not args.no_escalation,
        escalation_hop_depth=args.escalation_hop_depth,
    )
    ok = sum(1 for c in report.synth_calls if c.get("ok"))
    fail = sum(1 for c in report.synth_calls if not c.get("ok"))
    print(
        f"step3: project={report.project!r} cve={report.cve!r}"
        f" entrypoints_used={report.entrypoints_used}/{report.entrypoints_total}"
        f" irs={report.irs_produced} synth_ok={ok} synth_failed={fail}"
        f" elapsed={report.elapsed_sec:.1f}s -> {out_path}"
    )
    return 0


def _step4(args: argparse.Namespace) -> int:
    irs_path = Path(args.evidence_irs)
    source_root = Path(args.source)
    out_path = Path(args.out)
    if not irs_path.is_file():
        print(f"error: --evidence-irs not found: {irs_path}", file=sys.stderr)
        return 2
    if not source_root.is_dir():
        print(f"error: --source is not a directory: {source_root}", file=sys.stderr)
        return 2
    output, report = step4_runner.run(
        evidence_irs_path=irs_path,
        source_root=source_root,
        out_path=out_path,
        synth_chunk_size=args.synth_chunk_size,
        synth_max_workers=args.synth_max_workers,
    )
    chunk_note = (
        f" chunks={report.synth_call.get('succeeded')}/{report.synth_call.get('chunks')}"
        if report.chunked else ""
    )
    print(
        f"step4: project={report.project!r} cve={report.cve!r}"
        f" irs={report.irs_total} (with_sinks={report.irs_with_sinks})"
        f" scenarios={report.scenarios_produced}"
        f" synth_ok={report.synth_call.get('ok')}"
        f" chunked={report.chunked}{chunk_note}"
        f" elapsed={report.elapsed_sec:.1f}s -> {out_path}"
    )
    return 0


def _eval(args: argparse.Namespace) -> int:
    gold_dir = Path(args.gold)
    out_dir = Path(args.out_dir)
    report_path = Path(args.report) if args.report else None
    if not gold_dir.is_dir():
        print(f"error: --gold is not a directory: {gold_dir}", file=sys.stderr)
        return 2
    if not out_dir.is_dir():
        print(f"error: --out-dir is not a directory: {out_dir}", file=sys.stderr)
        return 2
    rep = eval_runner.run(
        gold_dir=gold_dir,
        out_dir=out_dir,
        eval_report_path=report_path,
        skip_step3=args.skip_step3,
        skip_step4=args.skip_step4,
    )
    s1 = rep.step1.get("overall_recall")
    s2 = rep.step2.get("gold_kept_recall_anywhere")
    s3 = rep.step3.get("equivalent_recall") if isinstance(rep.step3, dict) else None
    s4 = rep.step4.get("equivalent_recall") if isinstance(rep.step4, dict) else None
    all_pass = rep.exit_criteria.get("all_pass")
    print(
        f"eval: project={rep.project!r} cve={rep.cve!r}"
        f" step1_recall={s1} step2_recall_anywhere={s2}"
        f" step3_equivalent={s3} step4_equivalent={s4}"
        f" all_exit_criteria_pass={all_pass}"
        f" elapsed={rep.elapsed_sec:.1f}s"
    )
    if report_path:
        print(f" -> {report_path}")
    return 0 if all_pass else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
