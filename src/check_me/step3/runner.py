"""Step 3 end-to-end runner.

Loads:

  - ``substrate.json`` (Step 1 output) for retrieval
  - ``entrypoints.json`` (Step 2 output) for the kept entrypoint set
  - the project's source tree for code excerpt extraction

Produces ``evidence_irs.v1.json``: one IR per ``kept`` entrypoint.

Resilience mirrors Step 2's runner:

  - parallel dispatch (default ``max_workers=8``) tuned for the
    internal-LLM environment without per-minute quotas; drop to
    1 (sequential) on public-cloud providers with tight quotas
  - each IR synthesis call is wrapped; on raised exception a
    synthetic IR is recorded with confidence=low and uncertainty
    naming the failure, so a single transient hiccup does not
    abort the whole run (PLAN Rule 4 / silent-delete-forbidden)
  - up to ``synth_retry_passes=2`` sequential retry passes with
    a ``synth_retry_cooldown_sec=5`` cool-down between (was 60s
    when we were pacing under public-cloud per-minute quotas).

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
from .retrieval import DEFAULT_HOP_DEPTH, compute_neighborhood

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


def _demote_unanchored_sinks(ir: dict[str, Any]) -> list[str]:
    """Enforce the prompt-side rule "sink role REQUIRES a real
    non-zero, non-null line" by demoting violating sinks to
    ``intermediate`` and appending a structured warning to the
    IR's ``uncertainty``.

    Returns the list of demoted node identifiers (function names,
    or ``"<unnamed>"`` for nameless nodes) for diagnostic
    reporting.

    Project-agnostic: walks the schema's ``path.nodes`` and the
    enum value ``"sink"``; no project-name or symbol-pattern
    branching. The rule is that a sink is unusable for downstream
    Step 4 chain synthesis without a real harmful-operation line
    citation, regardless of which CVE produced the IR. Honest
    intermediate-only output is strictly more useful than a
    fabricated ``line: 0`` sink."""
    nodes = (ir.get("path") or {}).get("nodes") or []
    demoted: list[str] = []
    for n in nodes:
        if n.get("role") != "sink":
            continue
        line = n.get("line")
        if line is None or (isinstance(line, int) and line <= 0):
            n["role"] = "intermediate"
            demoted.append(n.get("function") or "<unnamed>")
    if demoted:
        warn = (
            "Sink role demoted to intermediate on node(s) "
            f"{demoted} because line was 0/null — no honest "
            "harmful-operation line citation. Step 4 chain "
            "synthesis should treat this IR as ending at an "
            "intermediate frame and weave with another IR rooted "
            "closer to the actual sink."
        )
        existing = ir.get("uncertainty") or ""
        ir["uncertainty"] = (existing + ("\n" if existing else "") + warn)[:1500]
    return demoted


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
    max_workers: int = 8,
    synth_retry_passes: int = 2,
    synth_retry_cooldown_sec: float = 5.0,
    enable_escalation: bool = True,
    escalation_hop_depth: int = DEFAULT_HOP_DEPTH + 1,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], Step3Report]:
    """Run Step 3 end-to-end on a single dataset's outputs.

    Returns ``(evidence_irs_json, report)``. Writes the output to
    ``out_path`` if supplied. The shape matches
    ``schemas/evidence_irs.v1.json``.

    Escalation (PLAN §3 Retrieval policy "N=2 + escalation"):
    when a per-IR LLM response sets ``needs_more_context: true``,
    the runner recomputes the neighborhood at
    ``escalation_hop_depth`` (default 3) and re-issues the
    synthesis call with the deeper input. The deeper IR replaces
    the original. ``enable_escalation=False`` reverts to a fixed
    N=2 retrieval (no recompute, no re-call) for budget-
    constrained runs. The signalling field itself is stripped
    from the persisted IR.
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

    def _attempt_at_depth(
        ep: dict[str, Any], hop_depth: int,
    ) -> tuple[dict[str, Any], int, int, int, int]:
        """Compute neighborhood at ``hop_depth``, extract
        excerpts, call synthesis. Returns
        (parsed_ir, nbhd_nodes, nbhd_edges, excerpts, attempts).
        Raises on transport / schema failure — caller handles."""
        nbhd = compute_neighborhood(
            substrate,
            entry_function=ep.get("function", ""),
            entry_file=ep.get("file", ""),
            entry_line=ep.get("line"),
            hop_depth=hop_depth,
        )
        targets = [(n.file, n.function) for n in nbhd.nodes if n.file]
        excerpts = extract_excerpts(source_root, targets)
        result = synth_mod.synthesise_ir(
            client=client, config=config,
            entrypoint=ep, neighborhood=nbhd, excerpts=excerpts,
            project=project, cve=cve,
            chat_fn=chat_fn,
        )
        return (
            result.parsed,
            len(nbhd.nodes), len(nbhd.edges), len(excerpts),
            result.attempts,
        )

    # Liveness counter, incremented on every entrypoint completion.
    _done = {"n": 0}
    _total = len(used_eps)

    def _synthesise_one(idx: int, ep: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, Any]]:
        """Compute neighborhood, extract excerpts, call synthesis,
        and (when ``enable_escalation``) re-call at deeper hops if
        the LLM sets ``needs_more_context: true``. Returns
        (idx, ir_dict, info). On exception ``info.ok`` is False
        and ir_dict is the synthetic placeholder."""
        t0 = time.monotonic()
        try:
            ir_parsed, n_nodes, n_edges, n_excerpts, attempts = _attempt_at_depth(
                ep, hop_depth=DEFAULT_HOP_DEPTH,
            )
            info: dict[str, Any] = {
                "ok": True,
                "candidate_id": ep.get("id"),
                "neighborhood_nodes": n_nodes,
                "neighborhood_edges": n_edges,
                "excerpts": n_excerpts,
                "attempts": attempts,
                "hop_depth": DEFAULT_HOP_DEPTH,
            }
            # Escalation — recompute at deeper hops + re-call when
            # the LLM signals insufficient context. We do this once
            # per IR (escalation depth is single-step from N=2 to
            # configured ``escalation_hop_depth`` — usually 3) so
            # an unconditional flag-loop cannot infinitely consume
            # budget.
            if (
                enable_escalation
                and bool(ir_parsed.get("needs_more_context"))
                and escalation_hop_depth > DEFAULT_HOP_DEPTH
            ):
                logger.info(
                    "step3: entrypoint %s requested more context — "
                    "re-call at hop_depth=%d (was %d at N=%d)",
                    ep.get("id"), escalation_hop_depth,
                    n_nodes, DEFAULT_HOP_DEPTH,
                )
                try:
                    deeper_ir, dn_nodes, dn_edges, dn_excerpts, dn_attempts = (
                        _attempt_at_depth(ep, hop_depth=escalation_hop_depth)
                    )
                    info.update({
                        "escalated": True,
                        "escalation_hop_depth": escalation_hop_depth,
                        "original_neighborhood_nodes": n_nodes,
                        "neighborhood_nodes": dn_nodes,
                        "neighborhood_edges": dn_edges,
                        "excerpts": dn_excerpts,
                        "attempts": attempts + dn_attempts,
                        "hop_depth": escalation_hop_depth,
                    })
                    ir_parsed = deeper_ir
                except Exception as esc_exc:  # noqa: BLE001
                    # Escalation failed — keep the N=2 IR and note
                    # the failure so operators can audit.
                    err = f"{type(esc_exc).__name__}: {esc_exc}"
                    logger.warning(
                        "step3: escalation failed for %s — keeping N=%d IR. %s",
                        ep.get("id"), DEFAULT_HOP_DEPTH, err[:200],
                    )
                    info["escalation_error"] = err[:300]
            # Strip the meta-signal so the persisted IR conforms
            # cleanly to the on-disk schema.
            ir_parsed.pop("needs_more_context", None)
            # Prompt-side rule says: sink role REQUIRES a non-zero,
            # non-null ``line`` (the actual harmful operation line).
            # Runner-side enforcement in case the LLM ignores it:
            # demote any sink-role node with line=0 or line=null
            # to ``intermediate`` and surface a structured warning
            # in ``uncertainty``. PLAN Rule 4 / silent-delete-
            # forbidden — we don't drop the node, we relabel it
            # so downstream Step 4 sees the chain end honestly.
            demoted = _demote_unanchored_sinks(ir_parsed)
            if demoted:
                info["unanchored_sinks_demoted"] = demoted
            elapsed = time.monotonic() - t0
            _done["n"] += 1
            sink_count = sum(
                1 for n in (ir_parsed.get("path") or {}).get("nodes", [])
                if n.get("role") == "sink"
            )
            logger.info(
                "step3: %d/%d %s entrypoint=%s nodes=%d sinks=%d"
                " escalated=%s elapsed=%.1fs",
                _done["n"], _total,
                ep.get("id"), ep.get("function"),
                info.get("neighborhood_nodes", 0),
                sink_count,
                bool(info.get("escalated")),
                elapsed,
            )
            return idx, ir_parsed, info
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            elapsed = time.monotonic() - t0
            err = f"{type(exc).__name__}: {exc}"
            _done["n"] += 1
            logger.warning(
                "step3: %d/%d %s entrypoint=%s FAILED elapsed=%.1fs err=%s",
                _done["n"], _total,
                ep.get("id"), ep.get("function"), elapsed, err[:120],
            )
            return idx, _synthetic_unverified_ir(
                entrypoint=ep, error_text=err,
            ), {
                "ok": False,
                "candidate_id": ep.get("id"),
                "error": err[:300],
            }

    # First pass — bounded parallelism (default sequential).
    logger.info(
        "step3: first pass — %d entrypoint(s), max_workers=%d, escalation=%s",
        _total, max_workers, enable_escalation,
    )
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
