"""Step 1 substrate runner.

Coordinates AST loading and per-category extraction. For Slice 1 the
only category implemented is ``call_graph``; the other six categories
are emitted as empty lists so the output already validates against
``schemas/substrate.v1.json``.

Future slices wire in the remaining extractors here.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import ast_index, call_graph


@dataclass
class RunReport:
    project_root: Path
    files_parsed: int
    parse_errors: int
    elapsed_sec: float
    edges_total: int
    edges_direct: int
    edges_indirect: int


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
    parse_errors = 0
    for spec in specs:
        parsed = ast_index.parse_file(index, spec)
        parse_errors += parsed.num_errors
        all_edges.extend(
            call_graph.extract_call_edges_from_tu(parsed, project_root)
        )

    edges = call_graph.merge_edges(all_edges)
    elapsed = time.monotonic() - started

    substrate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "project": project_name,
        "cve": cve,
        "categories": {
            "call_graph": [e.to_json() for e in edges],
            "data_control_flow": [],
            "guards": [],
            "trust_boundaries": [],
            "config_mode_command_triggers": [],
            "callback_registrations": [],
            "evidence_anchors": [],
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
    )
    return substrate, report


def write_substrate(substrate: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(substrate, indent=2) + "\n")
