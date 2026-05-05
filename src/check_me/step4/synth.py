"""LLM calls for Step 4 attack scenario synthesis.

Two execution modes share the same prompt + schema:

  - :func:`synthesise_scenarios` — single call. The LLM sees all
    Step 3 IRs and weaves scenarios from those whose ``confidence``
    is high/medium and whose path contains a ``sink`` role node.
    Suitable when sink-bearing IR count is small (≲ chunk_size).
  - :func:`synthesise_scenarios_chunked` — fixed-size chunks of
    sink-bearing IR ids, one fresh LLM session per chunk, results
    merged + deduped. Mirrors Step 2's chunked-miner pattern: at
    large IR scale (e.g. contiki's 76 confident sink IRs) a single
    holistic call drops 60+ scenarios silently no matter how the
    coverage rule is phrased; per-chunk Part A coverage with
    explicit assigned-id lists removes that failure mode.

Both modes use the same per-call ``synthesise_scenarios`` engine
and the same prompt builder (with ``assigned_ir_ids`` populated
appropriately).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from ..step2.miner import reasoning_extra
from .prompts import (
    SCENARIOS_OUTPUT_SCHEMA,
    build_synthesis_messages,
    collect_sink_bearing_ir_ids,
)

logger = logging.getLogger(__name__)


# Floor on first-attempt max_tokens. Step 4 scenarios are
# verbose: each one carries an exploit_chain (~2-6 steps with
# action+result text), a sink object, impact, verdict, and
# uncertainty. Five scenarios at ~800 visible JSON tokens each
# = ~4K visible tokens. With reasoning headroom on thinking
# models, 16384 is comfortable.
MIN_SYNTH_MAX_TOKENS = 16384


# Default temperature. Step 4 is the deterministic-synthesis
# half of the pipeline (Step 3 already did the substrate-walk
# work); same input → same scenarios. 0.0 matches the
# verifier and Step 3 synthesis posture.
DEFAULT_SYNTH_TEMPERATURE: float = 0.0


# Default number of sink-bearing IRs per chunked Step 4 call.
# Smaller than Step 2's chunked-miner default (30) because each
# Step 4 output element is significantly larger than a miner
# candidate row: a scenario carries an exploit_chain (~2-6 steps
# with action+result text), a sink object, impact, verdict, and
# uncertainty (~800 visible JSON tokens each). 15 keeps the
# per-chunk output under ~12K visible tokens with reasoning
# headroom. Override via ``chunk_size`` kwarg.
DEFAULT_CHUNK_SIZE = 15

# Concurrent chunked-Step-4 calls. Default 4 for the internal-LLM
# environment without per-minute quotas. Per-chunk inputs run
# 100-200K tokens on stack-style C codebases (full IR list +
# per-IR sink excerpts) — public-cloud users on tight per-minute
# input-token quotas should drop this to 1 sequential.
DEFAULT_MAX_WORKERS = 4


@dataclass
class ChunkedSynthResult:
    """Aggregated result of a chunked Step 4 run.

    ``parsed`` mimics ``CallResult.parsed`` so the runner can
    treat the chunked output identically to a single-call
    result: ``{"attack_scenarios": [...]}`` after dedupe and
    global id renumbering. ``per_chunk`` carries diagnostic
    data per chunk for the run report (token usage, retries,
    error if any, scenarios produced + kept after dedupe)."""
    parsed: dict[str, Any]
    per_chunk: list[dict[str, Any]]


def synthesise_scenarios(
    client: Any,
    config: Config,
    *,
    evidence_irs: list[dict[str, Any]],
    sink_excerpts: dict[str, str],
    project: str,
    cve: str,
    assigned_ir_ids: list[str] | None = None,
    chunk_index: int | None = None,
    chunk_total: int | None = None,
    max_retries: int = 2,
    max_tokens_ceiling: int = 131072,
    min_max_tokens: int = MIN_SYNTH_MAX_TOKENS,
    reasoning_effort: str | None = "high",
    temperature: float | None = DEFAULT_SYNTH_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """One Step 4 LLM call. Returns a ``CallResult`` whose
    ``parsed`` is ``{"attack_scenarios": [...]}``.

    ``assigned_ir_ids`` is forwarded to the prompt builder. When
    None, the prompt defaults to "every IR with a sink role and
    confidence high/medium" — preserves the pre-chunked
    behaviour. When chunked, the runner passes the per-chunk
    subset.
    """
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_synthesis_messages(
        project=project, cve=cve,
        evidence_irs=evidence_irs,
        sink_excerpts=sink_excerpts,
        assigned_ir_ids=assigned_ir_ids,
        chunk_index=chunk_index,
        chunk_total=chunk_total,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=SCENARIOS_OUTPUT_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )


def synthesise_scenarios_chunked(
    client: Any,
    config: Config,
    *,
    evidence_irs: list[dict[str, Any]],
    sink_excerpts: dict[str, str],
    project: str,
    cve: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_retries: int = 2,
    max_tokens_ceiling: int = 131072,
    min_max_tokens: int = MIN_SYNTH_MAX_TOKENS,
    reasoning_effort: str | None = "high",
    temperature: float | None = DEFAULT_SYNTH_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> ChunkedSynthResult:
    """Run Step 4 over fixed-size chunks of sink-bearing IR ids
    and merge the results.

    Each chunk gets a fresh LLM session whose Part A coverage
    rule applies only to its assigned IR ids. The full IR list
    is visible in every chunk's prompt as cross-chunk context
    so multi-IR weaves still work (e.g. an assigned entrypoint
    IR threading through a non-assigned downstream IR to a
    sink). After all chunks return, scenarios are deduped by
    ``(sink.function, sink.file, sink.sink_type, frozenset(
    evidence_ir ids in chain))`` so two chunks independently
    producing the same scenario don't double-count.

    ``chunk_size`` defaults to :data:`DEFAULT_CHUNK_SIZE`. Sort
    order for chunking is the IR id's natural string order so
    chunk membership is reproducible across runs.

    Determinism: assigned IR ids are sorted before chunking; the
    merged output is sorted by (sink.file, sink.function,
    sink.line) before global id renumbering so the result is
    stable regardless of chunk return order. Failed chunks
    contribute zero scenarios but their failure is recorded in
    ``per_chunk`` (PLAN Rule 4 — silent delete is forbidden).
    """
    sink_bearing_ids = sorted(collect_sink_bearing_ir_ids(evidence_irs))
    if not sink_bearing_ids:
        chunks: list[list[str]] = []
    else:
        chunks = [
            sink_bearing_ids[i:i + chunk_size]
            for i in range(0, len(sink_bearing_ids), chunk_size)
        ]

    logger.info(
        "step4.synth: chunked run — %d chunk(s) of size <= %d, max_workers=%d,"
        " %d sink-bearing IR(s)",
        len(chunks), chunk_size, max_workers, len(sink_bearing_ids),
    )

    chunk_total = len(chunks)

    def _run_chunk(idx: int, assigned: list[str]) -> tuple[int, CallResult | None, dict[str, Any] | None]:
        try:
            result = synthesise_scenarios(
                client=client, config=config,
                evidence_irs=evidence_irs,
                sink_excerpts=sink_excerpts,
                project=project, cve=cve,
                assigned_ir_ids=assigned,
                chunk_index=idx,
                chunk_total=chunk_total,
                max_retries=max_retries,
                max_tokens_ceiling=max_tokens_ceiling,
                min_max_tokens=min_max_tokens,
                reasoning_effort=reasoning_effort,
                temperature=temperature,
                chat_fn=chat_fn,
            )
            return idx, result, None
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            err = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "step4.synth: chunk %d failed (%d assigned IRs) — %s",
                idx, len(assigned), err[:200],
            )
            return idx, None, {"error": err[:300], "assigned_count": len(assigned)}

    chunk_results: list[CallResult | None] = [None] * len(chunks)
    chunk_errors: dict[int, dict[str, Any]] = {}
    if max_workers <= 1 or len(chunks) <= 1:
        for i, assigned in enumerate(chunks):
            _, r, err = _run_chunk(i, assigned)
            chunk_results[i] = r
            if err is not None:
                chunk_errors[i] = err
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_run_chunk, i, c) for i, c in enumerate(chunks)]
            for f in futs:
                idx, r, err = f.result()
                chunk_results[idx] = r
                if err is not None:
                    chunk_errors[idx] = err

    # Merge + dedupe.
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    per_chunk_diag: list[dict[str, Any]] = []
    for i, r in enumerate(chunk_results):
        if r is None:
            err_info = chunk_errors.get(i, {"error": "unknown"})
            per_chunk_diag.append({
                "chunk_index": i,
                "assigned": list(chunks[i]) if i < len(chunks) else [],
                "proposed": 0,
                "kept_after_dedupe": 0,
                "ok": False,
                "error": err_info.get("error", "unknown"),
            })
            continue
        proposed = (r.parsed or {}).get("attack_scenarios", []) or []
        chunk_keep = 0
        for sc in proposed:
            key = _scenario_dedupe_key(sc)
            if key in seen:
                continue
            seen.add(key)
            merged.append(sc)
            chunk_keep += 1
        per_chunk_diag.append({
            "chunk_index": i,
            "assigned": list(chunks[i]),
            "proposed": len(proposed),
            "kept_after_dedupe": chunk_keep,
            "ok": True,
            "attempts": r.attempts,
        })

    # Stable sort then global renumber so output ids are
    # independent of chunk return order.
    merged.sort(key=_scenario_sort_key)
    for j, sc in enumerate(merged, 1):
        sc["id"] = f"AS-{j:03d}"

    return ChunkedSynthResult(
        parsed={"attack_scenarios": merged},
        per_chunk=per_chunk_diag,
    )


def _scenario_dedupe_key(sc: dict[str, Any]) -> tuple[Any, ...]:
    """Dedupe key for cross-chunk merged scenarios.

    Two scenarios are duplicates when they reach the same harmful
    operation via the same IR set. ``(sink.function, sink.file,
    sink.line, sink.sink_type, frozenset of evidence_ir ids in
    exploit_chain.steps)`` matches the operator's intuition:
    different entrypoints reaching the same sink (UDP vs TCP)
    produce different IR id sets and stay distinct."""
    sink = sc.get("sink") or {}
    chain_steps = ((sc.get("exploit_chain") or {}).get("steps") or [])
    ir_ids = frozenset(
        s.get("evidence_ir") for s in chain_steps
        if isinstance(s.get("evidence_ir"), str)
    )
    return (
        sink.get("function"),
        sink.get("file"),
        sink.get("line"),
        sink.get("sink_type"),
        ir_ids,
    )


def _scenario_sort_key(sc: dict[str, Any]) -> tuple[Any, ...]:
    sink = sc.get("sink") or {}
    return (
        sink.get("file") or "",
        sink.get("function") or "",
        sink.get("line") or 0,
        sink.get("sink_type") or "",
    )
