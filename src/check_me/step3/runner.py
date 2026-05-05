"""Step 3 end-to-end runner.

Loads:

  - ``substrate.json`` (Step 1 output) for retrieval
  - ``entrypoints.json`` (Step 2 output) for the kept entrypoint set
  - the project's source tree for code excerpt extraction

Produces ``evidence_irs.v1.json``: one IR per ``kept`` entrypoint.

Resilience mirrors Step 2's runner:

  - sequential dispatch (default ``max_workers=1``) so per-minute
    provider quotas are not overrun
  - each IR synthesis call is wrapped; on raised exception a
    synthetic IR is recorded with confidence=low and uncertainty
    naming the failure, so a single transient hiccup does not
    abort the whole run (PLAN Rule 4 / silent-delete-forbidden)
  - up to ``synth_retry_passes=2`` sequential retry passes with
    a ``synth_retry_cooldown_sec=60`` cool-down between, letting
    rate-limit windows refill.

Quarantined entrypoints are NOT consumed by default (per CLAUDE.md
"Step 3 default 입력은 status: kept 행"); set
``include_quarantined=True`` to include them.
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat, make_client
from ..llm.config import Config, StepKind, load_config
from . import synth as synth_mod
from .code_excerpt import extract_excerpts
from .retrieval import compute_neighborhood

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "v1"


@dataclass
class Step3Report:
    project: str
    cve: str
    entrypoints_total: int
    entrypoints_used: int
    irs_produced: int
    synth_calls: list[dict[str, Any]] = field(default_factory=list)
    elapsed_sec: float = 0.0


def _synthetic_unverified_ir(
    *, entrypoint: dict[str, Any], error_text: str,
) -> dict[str, Any]:
    """Build a placeholder IR for an entrypoint whose synthesis
    call failed. PLAN Rule 4: silent-delete is forbidden — every
    kept entrypoint produces an IR even when the LLM call could
    not complete. The placeholder is honest about its origin so
    downstream Step 4 can detect and re-run as needed."""
    return {
        "id": "IR-tmp",  # overwritten by runner with global ID
        "entrypoint": {
            "function": entrypoint.get("function", "<unknown>"),
            "file": entrypoint.get("file", "<unknown>"),
            "line": entrypoint.get("line"),
        },
        "runtime_context": {
            "trigger_type": entrypoint.get("trigger_type", "unknown"),
            "trigger_ref": entrypoint.get("trigger_ref"),
            "config_flags": [],
        },
        "path": {
            "nodes": [{
                "function": entrypoint.get("function", "<unknown>"),
                "file": entrypoint.get("file", "<unknown>"),
                "line": entrypoint.get("line"),
                "role": "entry",
            }],
            "edges": [],
        },
        "conditions": {"required": [], "blocking": []},
        "evidence_anchors": [],
        "confidence": "low",
        "uncertainty": (
            f"Step 3 LLM synthesis call failed: {error_text}. "
            "This IR is a placeholder and does not reflect a real "
            "execution-path analysis. Downstream Step 4 should "
            "detect this prefix and re-run if needed."
        )[:600],
    }


def run(
    *,
    substrate_path: Path,
    entrypoints_path: Path,
    source_root: Path,
    out_path: Path | None = None,
    config: Config | None = None,
    client: Any | None = None,
    include_quarantined: bool = False,
    max_workers: int = 1,
    synth_retry_passes: int = 2,
    synth_retry_cooldown_sec: float = 60.0,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], Step3Report]:
    """Run Step 3 end-to-end on a single dataset's outputs.

    Returns ``(evidence_irs_json, report)``. Writes the output to
    ``out_path`` if supplied. The shape matches
    ``schemas/evidence_irs.v1.json``.
    """
    start = time.monotonic()

    substrate = json.loads(Path(substrate_path).read_text())
    entrypoints_doc = json.loads(Path(entrypoints_path).read_text())
    source_root = Path(source_root)

    project = substrate.get("project") or entrypoints_doc.get("project") or "<unknown>"
    cve = substrate.get("cve") or entrypoints_doc.get("cve") or "<unknown>"

    all_eps: list[dict[str, Any]] = entrypoints_doc.get("entrypoints", [])
    if include_quarantined:
        used_eps = list(all_eps)
    else:
        used_eps = [e for e in all_eps if e.get("status") == "kept"]
    logger.info(
        "step3: project=%s cve=%s — %d entrypoints (%d used after status filter)",
        project, cve, len(all_eps), len(used_eps),
    )

    if config is None:
        config = load_config(step=StepKind.STEP3)
    if client is None:
        client = make_client(config)

    def _synthesise_one(idx: int, ep: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, Any]]:
        """Compute neighborhood, extract excerpts, call synthesis.
        Returns (idx, ir_dict, info). On exception ``info.ok`` is
        False and ir_dict is the synthetic placeholder."""
        try:
            nbhd = compute_neighborhood(
                substrate,
                entry_function=ep.get("function", ""),
                entry_file=ep.get("file", ""),
                entry_line=ep.get("line"),
            )
            targets = [(n.file, n.function) for n in nbhd.nodes if n.file]
            excerpts = extract_excerpts(source_root, targets)
            result = synth_mod.synthesise_ir(
                client=client, config=config,
                entrypoint=ep, neighborhood=nbhd, excerpts=excerpts,
                project=project, cve=cve,
                chat_fn=chat_fn,
            )
            return idx, result.parsed, {
                "ok": True,
                "candidate_id": ep.get("id"),
                "neighborhood_nodes": len(nbhd.nodes),
                "neighborhood_edges": len(nbhd.edges),
                "excerpts": len(excerpts),
                "attempts": result.attempts,
            }
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            err = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "step3: IR synthesis failed for entrypoint %s — %s",
                ep.get("id"), err[:200],
            )
            return idx, _synthetic_unverified_ir(
                entrypoint=ep, error_text=err,
            ), {
                "ok": False,
                "candidate_id": ep.get("id"),
                "error": err[:300],
            }

    # First pass — bounded parallelism (default sequential).
    results: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    if max_workers <= 1 or len(used_eps) <= 1:
        for i, ep in enumerate(used_eps):
            results.append(_synthesise_one(i, ep))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_synthesise_one, i, ep) for i, ep in enumerate(used_eps)]
            results = [f.result() for f in futs]
            results.sort(key=lambda t: t[0])

    # Retry passes — sequentially re-attempt entrypoints whose first-pass
    # synthesis raised. Each pass preceded by a cooldown.
    for retry_pass in range(1, synth_retry_passes + 1):
        failed_indices = [i for i, _, info in results if not info.get("ok")]
        if not failed_indices:
            break
        logger.info(
            "step3: retry pass %d/%d on %d failed IR(s) — sleeping %.0fs",
            retry_pass, synth_retry_passes, len(failed_indices),
            synth_retry_cooldown_sec,
        )
        if synth_retry_cooldown_sec > 0:
            time.sleep(synth_retry_cooldown_sec)
        for i in failed_indices:
            ep = used_eps[i]
            new = _synthesise_one(i, ep)
            if new[2].get("ok"):
                results[i] = (new[0], new[1], {**new[2], "retry_pass": retry_pass})
            else:
                results[i] = (
                    new[0], new[1],
                    {**new[2], "retry_pass": retry_pass},
                )

    # Build the final IR list with global sequential IDs.
    irs: list[dict[str, Any]] = []
    synth_calls: list[dict[str, Any]] = []
    for i, ir, info in results:
        ir["id"] = f"IR-{i+1:03d}"
        irs.append(ir)
        synth_calls.append(info)

    elapsed = time.monotonic() - start
    output = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "cve": cve,
        "evidence_irs": irs,
    }
    if out_path is not None:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(output, indent=2) + "\n")

    report = Step3Report(
        project=project,
        cve=cve,
        entrypoints_total=len(all_eps),
        entrypoints_used=len(used_eps),
        irs_produced=len(irs),
        synth_calls=synth_calls,
        elapsed_sec=elapsed,
    )
    return output, report
