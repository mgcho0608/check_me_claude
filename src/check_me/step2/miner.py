"""Miner — discover entrypoint candidates the substrate cuts missed.

Architecture (post per-candidate-redundancy removal):

The deterministic substrate cuts (anchors + 1-hop closure +
call-graph roots — see ``substrate_slice.slice_substrate``) already
produce a candidate pool the runner forwards directly to the
verifier as deterministic synthetic rows. The miner therefore
does NOT re-enumerate substrate-origin candidates — that work is
pure redundancy because the verifier is anchoring-blind (PLAN §0
/ Rule 2b) and ignores miner-side reasoning. Instead the miner
focuses on cross-substrate DISCOVERY of entrypoints the cuts
missed: indexed dispatchers, runtime callback installations not
captured by the AST extractor, etc. The miner emits ONLY new
candidates (function names not in the known pool); empty output
is the common and correct case.

Implementation: chunk the candidate list to bound per-call
substrate-projection size on large projects, issue one fresh LLM
call per chunk in parallel (each chunk sees a chunk-projected
substrate slice plus the FULL known-candidates list — the
discovery scope is global, the projection is local for token
budget), then merge new discoveries across chunks deduping by
``(function, file)``. Final dedup against known_candidates
filters out any function name the LLM emitted despite the
explicit instruction. Renumber ids globally as ``EP-001`` …
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Callable

from ..audit_log import AuditLog
from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import MINER_OUTPUT_SCHEMA, build_miner_messages
from .substrate_slice import SubstrateSlice, slice_for_candidate_chunk

logger = logging.getLogger(__name__)


# Floor for any single miner call's max_tokens. Chunked execution
# means each call emits ~30 candidate rows of structured JSON; with
# reasoning-token overhead and slack 16384 is comfortable. Operator
# env values higher than the floor are respected; lower values are
# bumped up.
MIN_MINER_MAX_TOKENS = 16384

# How many candidate names go to a single miner call. Smaller chunks
# force the LLM to engage with each candidate (avoids the "skim and
# pick top-N" behaviour observed at higher counts). 30 was chosen
# empirically — 20-50 is a reasonable range. Override via the
# ``chunk_size`` kwarg on ``mine_chunked``. Project-agnostic; no
# dataset-specific tuning.
DEFAULT_CHUNK_SIZE = 30

# Concurrent miner / verifier calls. The OpenAI SDK is thread-safe.
#
# Default tuned for the internal-LLM environment (no per-minute
# input-token quota): 8 concurrent chunks. Public-cloud Gemini
# users with strict per-minute quotas (e.g. 2M/min) should drop
# this to 1 — see runner kwargs / env-var overrides. The previous
# default was 1 (sequential) precisely because the miner's
# per-chunk input can run 100-200K tokens on stack-style C
# codebases and concurrent dispatch burst past public-cloud
# quotas; the sweet spot is provider-dependent. Raised from 4 to
# 8 after empirical measurement on a stack-style project (per-
# candidate verifier average ~2 minutes at workers=4) showed
# the internal-LLM server handled additional concurrency without
# per-request slowdown; 8 keeps total wall-clock bounded while
# staying short of the server's serving-capacity ceiling.
DEFAULT_MAX_WORKERS = 8


# Default temperature for miner calls. PLAN proposer/verifier split:
# miner = creative recall (some randomness helps cross-chunk
# discovery), verifier = rigorous filter (deterministic). 0.1 keeps
# miner output stable enough for testing while leaving room for
# discovery. Operator env values are honoured if they differ.
DEFAULT_MINER_TEMPERATURE: float = 0.1


@dataclass
class ChunkedMineResult:
    """Aggregated result of a chunked miner run.

    ``parsed`` mimics ``CallResult.parsed`` so the runner can treat
    the chunked output identically to a single-call result.
    ``per_chunk`` carries diagnostic data per chunk for the run
    report (token usage, retries, discovery counts).
    """
    parsed: dict[str, Any]
    per_chunk: list[dict[str, Any]]


def reasoning_extra(reasoning_effort: str | None) -> dict[str, Any]:
    """Build a ``request.extra`` dict that caps internal-reasoning
    tokens via the OpenAI standard ``reasoning_effort`` field.
    Providers that don't recognise the field silently ignore it.
    Runtime knob, not project-specific."""
    if reasoning_effort is None:
        return {}
    return {"reasoning_effort": reasoning_effort}


def mine(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    *,
    max_retries: int = 2,
    max_tokens_ceiling: int = 131072,
    min_max_tokens: int = MIN_MINER_MAX_TOKENS,
    reasoning_effort: str | None = "high",
    temperature: float | None = DEFAULT_MINER_TEMPERATURE,
    chunk: list[str] | None = None,
    known_candidates: list[str] | None = None,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Run a single miner LLM call (discovery only).

    For production, use :func:`mine_chunked`, which calls this in
    parallel across chunks. ``mine`` is exposed for tests and for
    one-shot mining when the candidate count is small.

    ``chunk``: substrate-projection focus list. If None, the miner
    sees the full slice (single-call mode — used by tests and by
    very small projects).

    ``known_candidates``: project-wide list of function names
    already in the deterministic synthetic pool. The miner is
    forbidden from re-emitting these. When None, the slice's own
    ``candidate_functions`` is used as the known set.

    ``temperature``: overrides ``config.temperature`` if not None.
    The miner default is 0.1 — see :data:`DEFAULT_MINER_TEMPERATURE`.

    ``min_max_tokens``: first-attempt floor for ``max_tokens``. See
    :data:`MIN_MINER_MAX_TOKENS`.
    """
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_miner_messages(
        slice_, chunk=chunk, known_candidates=known_candidates,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=MINER_OUTPUT_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )


def mine_chunked(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_retries: int = 2,
    max_tokens_ceiling: int = 131072,
    min_max_tokens: int = MIN_MINER_MAX_TOKENS,
    reasoning_effort: str | None = "high",
    temperature: float | None = DEFAULT_MINER_TEMPERATURE,
    use_chunk_focused_slice: bool = True,
    chunk_hop_depth: int = 1,
    audit_log: AuditLog | None = None,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> ChunkedMineResult:
    """Run the discovery miner over fixed-size chunks of the
    candidate list, in parallel, and merge results.

    The candidate list is the project-wide deterministic pool
    (anchors + 1-hop closure + roots from substrate cuts). Each
    chunk's slice projects substrate around its assigned subset
    so the per-call substrate prompt stays bounded. Each chunk
    also receives the FULL pool as ``known_candidates`` — the
    miner is told to discover NEW entrypoints and never re-emit
    a known one. Final dedup against the known set filters out
    any LLM slip-ups.

    ``chunk_hop_depth`` defaults to 1 — see
    :func:`slice_for_candidate_chunk` for the rationale. The miner
    looks at direct 1-hop neighbourhood evidence; deeper chain
    validation is the verifier's job (per-candidate hop=1 source
    excerpts on the verifier side).

    Determinism: the candidate list is sorted before chunking, so
    chunk membership is reproducible. Within a chunk, the LLM's
    output ordering depends on its temperature setting (default
    0.1). After merge, candidates are sorted by ``(file, function)``
    for stable serialisation.
    """
    if audit_log is None:
        audit_log = AuditLog.disabled()
    candidates = sorted(slice_.candidate_functions)
    known_candidates = list(candidates)  # full project pool, not chunk
    if not candidates:
        chunks: list[list[str]] = []
    else:
        chunks = [
            candidates[i:i + chunk_size]
            for i in range(0, len(candidates), chunk_size)
        ]

    logger.info(
        "step2.miner: chunked run — %d chunks of size <= %d, max_workers=%d",
        len(chunks), chunk_size, max_workers,
    )

    import time as _time

    def _run_chunk(chunk_idx: int, chunk: list[str]) -> tuple[int, CallResult | None, dict[str, Any] | None]:
        """Run one miner chunk. On exception (e.g. exhausted 429
        retry budget) return (idx, None, error_info) so the merge
        loop can record the failure and proceed; the surviving
        chunks still produce candidates and the run completes
        instead of aborting on a single transient hiccup. PLAN
        Rule 4: silent delete is forbidden — the per-chunk
        diagnostic records the error so the operator can re-run.

        The slice handed to ``mine`` is chunk-focused by default
        (per-chunk projection over the full slice via
        :func:`slice_for_candidate_chunk`) so the per-call prompt
        stays under the model's context window on large projects.
        Set ``use_chunk_focused_slice=False`` on
        :func:`mine_chunked` to revert to the pre-projection
        behaviour — see PLAN.md Appendix A "Known risk: chunk
        slice scoping" for when this escape hatch is appropriate.
        """
        t0 = _time.monotonic()
        if use_chunk_focused_slice:
            chunk_slice = slice_for_candidate_chunk(
                slice_,
                chunk_candidates=chunk,
                hop_depth=chunk_hop_depth,
            )
        else:
            chunk_slice = slice_
        try:
            result = mine(
                client=client,
                config=config,
                slice_=chunk_slice,
                chunk=chunk,
                known_candidates=known_candidates,
                max_retries=max_retries,
                max_tokens_ceiling=max_tokens_ceiling,
                min_max_tokens=min_max_tokens,
                reasoning_effort=reasoning_effort,
                temperature=temperature,
                chat_fn=chat_fn,
            )
            elapsed = _time.monotonic() - t0
            proposed = len((result.parsed or {}).get("candidates", []))
            logger.info(
                "step2.miner: chunk %d/%d done assigned=%d proposed=%d"
                " attempts=%d elapsed=%.1fs",
                chunk_idx + 1, len(chunks), len(chunk), proposed,
                len(result.attempts), elapsed,
            )
            audit_log.append({
                "stage": "step2.miner",
                "chunk_index": chunk_idx,
                "chunk_size": len(chunk),
                "proposed": proposed,
                "elapsed_sec": round(elapsed, 2),
                "attempts": len(result.attempts),
                "ok": True,
            })
            return chunk_idx, result, None
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            elapsed = _time.monotonic() - t0
            err = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "step2.miner: chunk %d/%d FAILED assigned=%d elapsed=%.1fs err=%s",
                chunk_idx + 1, len(chunks), len(chunk), elapsed, err[:120],
            )
            audit_log.append({
                "stage": "step2.miner",
                "chunk_index": chunk_idx,
                "chunk_size": len(chunk),
                "elapsed_sec": round(elapsed, 2),
                "ok": False,
                "error": err[:300],
            })
            return chunk_idx, None, {"error": err[:300], "chunk_size": len(chunk)}

    chunk_results: list[CallResult | None] = [None] * len(chunks)
    chunk_errors: dict[int, dict[str, Any]] = {}
    if max_workers <= 1 or len(chunks) <= 1:
        for i, chunk in enumerate(chunks):
            _, r, err = _run_chunk(i, chunk)
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

    # Merge across chunks, dedupe by (function, file), AND filter
    # out any candidate whose function name is in the known pool —
    # the LLM is instructed not to re-emit known names but final
    # filter ensures correctness. Failed chunks contribute zero
    # candidates but their failure is recorded in per_chunk_diag.
    known_set = set(known_candidates)
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()
    per_chunk_diag: list[dict[str, Any]] = []
    for i, r in enumerate(chunk_results):
        if r is None:
            err_info = chunk_errors.get(i, {"error": "unknown"})
            per_chunk_diag.append({
                "chunk_index": i,
                "chunk_size": err_info.get("chunk_size", len(chunks[i]) if i < len(chunks) else 0),
                "proposed": 0,
                "kept_after_dedupe": 0,
                "ok": False,
                "error": err_info.get("error", "unknown"),
            })
            continue
        proposed = r.parsed.get("candidates", []) if r.parsed else []
        chunk_keep = 0
        chunk_dropped_known = 0
        for cand in proposed:
            fn = cand.get("function")
            # Strip out any function the LLM emitted despite the
            # explicit "do NOT emit known" instruction.
            if isinstance(fn, str) and fn in known_set:
                chunk_dropped_known += 1
                continue
            key = (fn, cand.get("file"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(cand)
            chunk_keep += 1
        per_chunk_diag.append({
            "chunk_index": i,
            "chunk_size": len(chunks[i]),
            "proposed": len(proposed),
            "dropped_already_known": chunk_dropped_known,
            "kept_after_dedupe": chunk_keep,
            "ok": True,
            "attempts": r.attempts,
        })

    # Stable sort for determinism. ID assignment is deferred to the
    # runner — it merges synthetic + miner output before
    # renumbering globally.
    merged.sort(key=lambda c: (c.get("file") or "", c.get("function") or ""))

    return ChunkedMineResult(
        parsed={"candidates": merged},
        per_chunk=per_chunk_diag,
    )
