"""Step 1 substrate runner.

Coordinates AST loading and dispatches each parsed translation
unit to the seven per-category extractors. Output is a single
JSON document validated against ``schemas/substrate.v1.json``.

Categories (all implemented):

- ``call_graph`` — direct + indirect ``CallExpr`` edges
  (``call_graph.py``).
- ``data_control_flow`` — branch / loop / def_use entries
  (``data_control_flow.py``).
- ``guards`` — if-with-terminating-then constructs
  (``guards.py``).
- ``trust_boundaries`` — functions that directly invoke a known
  POSIX / libc external-I/O API (``trust_boundaries.py``).
- ``callback_registrations`` — function tables, function-pointer
  assignments, signal handlers, constructor attributes
  (``callback_registrations.py``).
- ``config_mode_command_triggers`` — ``#ifdef``-family directives
  and ``-D`` build flags (``config_triggers.py``).
- ``evidence_anchors`` — magic-value macros and structural
  artefacts (struct / union / enum / typedef definitions, named
  fields, top-level VarDecls, alias macros)
  (``evidence_anchors.py``).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import (
    ast_index,
    call_graph,
    callback_registrations,
    config_triggers,
    data_control_flow,
    evidence_anchors,
    guards,
    trust_boundaries,
)


@dataclass
class RunReport:
    project_root: Path
    files_parsed: int
    parse_errors: int
    elapsed_sec: float
    edges_total: int
    edges_direct: int
    edges_indirect: int
    dcf_total: int
    dcf_branch: int
    dcf_loop: int
    dcf_def_use: int
    guards_total: int
    trust_total: int
    callbacks_total: int
    config_total: int
    anchors_total: int


SCHEMA_VERSION = "v1"


def run(
    project_root: Path,
    *,
    project_name: str,
    cve: str,
    extra_args: tuple[str, ...] = (),
) -> tuple[dict[str, Any], RunReport]:
    """Run Step 1 over a project tree and return (substrate_json, report).

    ``extra_args`` is forwarded to clang only on files that lack a
    ``compile_commands.json`` entry. Use it to inject ``-D`` /
    ``-I`` flags for projects that depend on a CMake/autoconf
    configuration step we did not run.
    """
    project_root = project_root.resolve()
    started = time.monotonic()

    index = ast_index.make_index()
    specs = ast_index.build_file_specs(project_root, extra_args=extra_args)

    all_edges: list[call_graph.CallEdge] = []
    all_dcf: list[data_control_flow.DCFEntry] = []
    all_guards: list[guards.GuardEntry] = []
    all_tb: list[trust_boundaries.TrustBoundary] = []
    all_cb: list[callback_registrations.CallbackReg] = []
    all_anchors: list[evidence_anchors.Anchor] = []
    parse_errors = 0
    for spec in specs:
        parsed = ast_index.parse_file(index, spec)
        parse_errors += parsed.num_errors
        all_edges.extend(
            call_graph.extract_call_edges_from_tu(parsed, project_root)
        )
        all_dcf.extend(
            data_control_flow.extract_dcf_from_tu(parsed, project_root)
        )
        all_guards.extend(
            guards.extract_guards_from_tu(parsed, project_root)
        )
        all_tb.extend(
            trust_boundaries.extract_trust_boundaries_from_tu(
                parsed, project_root
            )
        )
        all_cb.extend(
            callback_registrations.extract_callback_regs_from_tu(
                parsed, project_root
            )
        )
        all_anchors.extend(
            evidence_anchors.extract_anchors_from_tu(parsed, project_root)
        )

    edges = call_graph.merge_edges(all_edges)
    dcf = data_control_flow.merge_dcf(all_dcf)
    guard_rows = guards.merge_guards(all_guards)
    tb_rows = trust_boundaries.merge_trust_boundaries(all_tb)
    cb_rows = callback_registrations.merge_callback_regs(all_cb)
    cfg_rows = config_triggers.merge_config_triggers(
        config_triggers.extract_config_triggers(project_root, specs)
    )
    anchor_rows = evidence_anchors.merge_anchors(all_anchors)
    elapsed = time.monotonic() - started

    substrate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "project": project_name,
        "cve": cve,
        "categories": {
            "call_graph": [e.to_json() for e in edges],
            "data_control_flow": [e.to_json() for e in dcf],
            "guards": [e.to_json() for e in guard_rows],
            "trust_boundaries": [e.to_json() for e in tb_rows],
            "config_mode_command_triggers": [
                e.to_json() for e in cfg_rows
            ],
            "callback_registrations": [e.to_json() for e in cb_rows],
            "evidence_anchors": [e.to_json() for e in anchor_rows],
        },
    }
    report = RunReport(
        project_root=project_root,
        files_parsed=len(specs),
        parse_errors=parse_errors,
        elapsed_sec=elapsed,
        edges_total=len(edges),
        edges_direct=sum(1 for e in edges if e.kind == "direct"),
        edges_indirect=sum(1 for e in edges if e.kind == "indirect"),
        dcf_total=len(dcf),
        dcf_branch=sum(1 for d in dcf if d.kind == "branch"),
        dcf_loop=sum(1 for d in dcf if d.kind == "loop"),
        dcf_def_use=sum(1 for d in dcf if d.kind == "def_use"),
        guards_total=len(guard_rows),
        trust_total=len(tb_rows),
        callbacks_total=len(cb_rows),
        config_total=len(cfg_rows),
        anchors_total=len(anchor_rows),
    )
    return substrate, report


def write_substrate(substrate: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(substrate, indent=2) + "\n")
