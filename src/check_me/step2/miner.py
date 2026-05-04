"""Miner — propose entrypoint candidates from a substrate slice.

Architecture (PLAN §0 / Step 2 lossless):

The miner emits one row per function in the slice's
``candidate_functions`` plus any additional rows it discovers from
cross-chunk substrate patterns (most importantly the indexed-dispatch
shape — see ``prompts._MINER_SYSTEM`` Part B). Selection is the
verifier's job; the miner's job is to make sure every candidate
gets the verifier's eyes. False negatives at the miner stage are
unrecoverable — the verifier never sees what the miner didn't
propose.

Implementation: chunk the candidate list into fixed-size groups,
issue one fresh LLM call per chunk in parallel (each chunk sees the
full substrate slice as context but only its own assigned subset
to enumerate), then merge the per-chunk candidate lists deduping by
``(function, file)``. Renumber ids globally as ``EP-001``, ``EP-002``,
… so the output is consistent regardless of chunk boundary.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import MINER_OUTPUT_SCHEMA, build_miner_messages
from .substrate_slice import SubstrateSlice

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

# Concurrent miner / verifier calls. The OpenAI SDK is thread-safe;
# the Gemini OpenAI-compat surface enforces a per-minute input-token
# quota (2M/min on gemini-3-flash at the time of writing).
#
# Default 1 = sequential dispatch. The miner's per-chunk input
# (full substrate slice + chunk-specific user message) can run
# 100-200K tokens on stack-style C codebases; even 2 concurrent
# chunks burst past the per-minute quota when the slice is large.
# Sequential dispatch naturally paces under quota and works
# reliably across all dataset sizes. Raise via the runner's
# ``miner_max_workers`` kwarg if your provider's quota allows.
DEFAULT_MAX_WORKERS = 1


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
    max_tokens_ceiling: int = 65536,
    min_max_tokens: int = MIN_MINER_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    temperature: float | None = DEFAULT_MINER_TEMPERATURE,
    chunk: list[str] | None = None,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Run a single miner LLM call.

    For production, use :func:`mine_chunked`, which calls this in
    parallel across chunks. ``mine`` is exposed for tests and for
    one-shot mining when the candidate count is small.

    ``chunk``: assigned-candidates list for this call. If None, the
    miner is told to enumerate every function in ``candidate_functions``
    (single-call mode — used by tests and by very small projects).

    ``temperature``: overrides ``config.temperature`` if not None.
    The miner default is 0.1 — see :data:`DEFAULT_MINER_TEMPERATURE`.

    ``min_max_tokens``: first-attempt floor for ``max_tokens``. See
    :data:`MIN_MINER_MAX_TOKENS`.
    """
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_miner_messages(slice_, chunk=chunk)
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
    max_tokens_ceiling: int = 65536,
    min_max_tokens: int = MIN_MINER_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    temperature: float | None = DEFAULT_MINER_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> ChunkedMineResult:
    """Run the miner over fixed-size chunks of the candidate list,
    in parallel, and merge results.

    Per the lossless Step 2 architecture, every function in
    ``slice_.candidate_functions`` is sent to some chunk's miner
    call (Part A); each chunk also gets a discovery instruction
    (Part B). The merged candidate list dedupes by
    ``(function, file)`` and renumbers ids globally.

    Determinism: the candidate list is sorted before chunking, so
    chunk membership is reproducible. Within a chunk, the LLM's
    output ordering depends on its temperature setting (default
    0.1). After merge, candidates are sorted by ``(file, function)``
    for stable serialisation.
    """
    candidates = sorted(slice_.candidate_functions)
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

    def _run_chunk(chunk_idx: int, chunk: list[str]) -> tuple[int, CallResult | None, dict[str, Any] | None]:
        """Run one miner chunk. On exception (e.g. exhausted 429
        retry budget) return (idx, None, error_info) so the merge
        loop can record the failure and proceed; the surviving
        chunks still produce candidates and the run completes
        instead of aborting on a single transient hiccup. PLAN
        Rule 4: silent delete is forbidden — the per-chunk
        diagnostic records the error so the operator can re-run."""
        try:
            result = mine(
                client=client,
                config=config,
                slice_=slice_,
                chunk=chunk,
                max_retries=max_retries,
                max_tokens_ceiling=max_tokens_ceiling,
                min_max_tokens=min_max_tokens,
                reasoning_effort=reasoning_effort,
                temperature=temperature,
                chat_fn=chat_fn,
            )
            return chunk_idx, result, None
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            err = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "step2.miner: chunk %d failed (%d candidates) — %s",
                chunk_idx, len(chunk), err[:200],
            )
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

    # Merge and dedupe by (function, file). Failed chunks contribute
    # zero candidates but their failure is recorded in per_chunk_diag.
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
        for cand in proposed:
            key = (cand.get("function"), cand.get("file"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(cand)
            chunk_keep += 1
        per_chunk_diag.append({
            "chunk_index": i,
            "chunk_size": len(chunks[i]),
            "proposed": len(proposed),
            "kept_after_dedupe": chunk_keep,
            "ok": True,
            "attempts": r.attempts,
        })

    # Stable sort for determinism, then renumber ids EP-001, EP-002, …
    merged.sort(key=lambda c: (c.get("file") or "", c.get("function") or ""))
    for i, cand in enumerate(merged, 1):
        cand["id"] = f"EP-{i:03d}"

    return ChunkedMineResult(
        parsed={"candidates": merged},
        per_chunk=per_chunk_diag,
    )
