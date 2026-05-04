"""Step 2 end-to-end runner.

Loads a Step 1 substrate, slices it, runs the miner, runs the
verifier on each candidate (in a fresh LLM session per candidate),
combines the verdicts, and emits a JSON document conforming to
``schemas/entrypoints.v1.json``.

This module intentionally has no I/O concerns beyond reading a
substrate file and writing the output file. The LLM client is
injected so tests can stub it.
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
from . import miner as miner_mod
from . import verifier as verifier_mod
from .substrate_slice import (
    SubstrateSlice,
    slice_for_candidate,
    slice_substrate,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "v1"


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class RunReport:
    project: str
    cve: str
    slice_counts: dict[str, int]
    miner_chunks: list[dict[str, Any]]
    candidates_proposed: int
    verifier_calls: list[dict[str, Any]] = field(default_factory=list)
    kept: int = 0
    quarantined: int = 0
    elapsed_sec: float = 0.0


# --------------------------------------------------------------------------- #
# End-to-end
# --------------------------------------------------------------------------- #


def run(
    substrate: dict[str, Any] | str | Path,
    *,
    miner_config: Config | None = None,
    verifier_config: Config | None = None,
    miner_client: Any | None = None,
    verifier_client: Any | None = None,
    miner_chunk_size: int = miner_mod.DEFAULT_CHUNK_SIZE,
    miner_max_workers: int = miner_mod.DEFAULT_MAX_WORKERS,
    verifier_max_workers: int = 1,
    verifier_retry_passes: int = 2,
    verifier_retry_cooldown_sec: float = 60.0,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], RunReport]:
    """Run Step 2 end-to-end (lossless architecture).

    Step 2's miner is chunked: every function in the substrate
    slice's ``candidate_functions`` is sent through some chunk's
    miner call. Each chunk also carries an explicit cross-chunk
    discovery instruction so the LLM can propose entrypoints
    outside the candidate set when it spots cross-substrate
    patterns (indexed dispatchers etc.). The merged candidate list
    is then verified — every row receives an independent verifier
    critique with anchoring prevention.

    Resilience: a single verifier failure does not kill the whole
    run. Each verifier call is wrapped; on raised exception (e.g.
    LLM rate-limit retries exhausted), the candidate gets a
    synthetic ``quarantined`` verdict whose ``quarantine_reason``
    records the failure type. After the main pass, the runner
    sweeps ``verifier_retry_passes`` more times sequentially over
    the still-failed candidates with a ``verifier_retry_cooldown_sec``
    sleep between passes (lets per-minute provider quotas refill).
    Candidates that succeed in a retry get the real verifier
    verdict; candidates that exhaust all retries keep the synthetic
    quarantine — never silent-deleted, audit trail preserved per
    PLAN Rule 4.

    ``verifier_max_workers`` defaults to ``1`` (sequential):
    candidate counts can be in the hundreds on stack-style C
    codebases, and concurrent calls burst against per-minute
    provider quotas. Sequential dispatch naturally paces under
    quota; the retry passes handle transient hiccups.
    ``miner_max_workers`` keeps the parallel default since chunk
    counts are small (single-digit on typical projects).

    Configs and clients are optional — if not supplied, the runner
    loads them from the environment and constructs OpenAI SDK
    clients. Tests pass stubbed values.

    Returns
    -------
    (entrypoints_json, report)
        ``entrypoints_json`` matches ``schemas/entrypoints.v1.json``.
    """
    start = time.monotonic()
    slice_ = slice_substrate(substrate)

    if miner_config is None:
        miner_config = load_config(step=StepKind.STEP2_MINER)
    if verifier_config is None:
        verifier_config = load_config(step=StepKind.STEP2_VERIFIER)
    if miner_client is None:
        miner_client = make_client(miner_config)
    if verifier_client is None and verifier_config is not miner_config:
        verifier_client = make_client(verifier_config)
    if verifier_client is None:
        # Same config -> separate client objects anyway, so a fresh
        # SDK session is used (Rule 2b: the verifier must not see
        # the miner's chain of thought, which is enforced both by
        # the candidate-key stripping AND by using a fresh client
        # so any client-side state is isolated).
        verifier_client = make_client(verifier_config)

    # 1. Miner (chunked, parallel) -------------------------------------------
    logger.info("step2.miner: starting on slice %s", slice_.row_counts())
    miner_result = miner_mod.mine_chunked(
        client=miner_client,
        config=miner_config,
        slice_=slice_,
        chunk_size=miner_chunk_size,
        max_workers=miner_max_workers,
        chat_fn=chat_fn,
    )
    proposed: list[dict[str, Any]] = miner_result.parsed.get("candidates", [])
    logger.info(
        "step2.miner: %d chunks -> %d unique candidate(s)",
        len(miner_result.per_chunk), len(proposed),
    )

    # 2. Verifier (parallel first pass, sequential retry passes) ------------
    # Per PLAN §0 / Rule 2b the verifier critiques ONE candidate at
    # a time on a focused per-candidate sub-slice; the slice walk
    # is a deterministic substrate operation, the verifier call is
    # an LLM critique. Both run independently per candidate, so
    # they parallelise naturally.
    #
    # Resilience: each call is wrapped — on failure we emit a
    # synthetic quarantined verdict with the failure recorded in
    # ``quarantine_reason``. After the main pass, the runner
    # sweeps the still-failed entries up to ``verifier_retry_passes``
    # more times sequentially with a cooldown between passes so
    # provider quotas can refill.
    def _attempt_verify(cand: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Return (cand, verdict, info). info has ``ok: bool`` and
        either ``attempts`` (on success) or ``error`` (on failure).
        On failure a synthetic quarantined verdict is returned so
        the run never partially-fails."""
        focused = slice_for_candidate(
            slice_,
            candidate_function=cand.get("function", ""),
            candidate_file=cand.get("file"),
        )
        try:
            v_result = verifier_mod.verify_one(
                client=verifier_client,
                config=verifier_config,
                slice_=focused,
                candidate=cand,
                chat_fn=chat_fn,
            )
            return cand, v_result.parsed, {"ok": True, "attempts": v_result.attempts}
        except Exception as exc:  # noqa: BLE001 — capture-all is the design
            err_text = f"{type(exc).__name__}: {exc}"
            synthetic = _synthetic_unverified_verdict(err_text)
            return cand, synthetic, {"ok": False, "error": err_text[:300]}

    # First pass — bounded parallelism (default sequential for verifier).
    if verifier_max_workers <= 1 or len(proposed) <= 1:
        verdicts = [_attempt_verify(c) for c in proposed]
    else:
        with ThreadPoolExecutor(max_workers=verifier_max_workers) as ex:
            futs = [(i, ex.submit(_attempt_verify, c)) for i, c in enumerate(proposed)]
            verdicts_indexed = [(i, f.result()) for i, f in futs]
            verdicts_indexed.sort(key=lambda p: p[0])
            verdicts = [v for _, v in verdicts_indexed]

    # Retry passes — sequentially re-attempt candidates whose first-pass
    # verifier raised. Each pass is preceded by a cooldown so transient
    # rate-limit windows can refill. Successful retries replace the
    # synthetic verdict with the real one.
    for retry_pass in range(1, verifier_retry_passes + 1):
        failed_indices = [
            i for i, (_, _, info) in enumerate(verdicts) if not info.get("ok")
        ]
        if not failed_indices:
            break
        logger.info(
            "step2.verifier: retry pass %d/%d on %d failed candidate(s)"
            " — sleeping %.0fs first for quota cooldown",
            retry_pass, verifier_retry_passes,
            len(failed_indices), verifier_retry_cooldown_sec,
        )
        if verifier_retry_cooldown_sec > 0:
            time.sleep(verifier_retry_cooldown_sec)
        for i in failed_indices:
            cand = verdicts[i][0]
            new_result = _attempt_verify(cand)
            if new_result[2].get("ok"):
                # Successful retry — overwrite synthetic verdict with the
                # real one. Record retry pass for diagnostics.
                _, real_verdict, info = new_result
                info = {**info, "retry_pass": retry_pass}
                verdicts[i] = (cand, real_verdict, info)
            else:
                # Still failing — keep synthetic but update reason text
                # to reflect the retry budget consumed.
                _, synthetic, info = new_result
                synthetic = {
                    **synthetic,
                    "quarantine_reason": (
                        f"verifier unreachable after {retry_pass} retry pass(es): "
                        f"{info.get('error', 'unknown error')}"
                    )[:600],
                }
                info = {**info, "retry_pass": retry_pass}
                verdicts[i] = (cand, synthetic, info)

    # Build final entries from (possibly-retried) verdicts.
    final_entries: list[dict[str, Any]] = [None] * len(proposed)  # type: ignore[list-item]
    verifier_calls: list[dict[str, Any]] = [None] * len(proposed)  # type: ignore[list-item]
    kept = 0
    quarantined = 0

    for i, (cand, verdict, info) in enumerate(verdicts):
        merged = _merge_candidate_verdict(cand, verdict)
        final_entries[i] = merged
        if merged["status"] == "kept":
            kept += 1
        else:
            quarantined += 1
        verifier_calls[i] = {
            "candidate_id": cand.get("id"),
            "verdict": verdict.get("verdict"),
            **info,
        }

    elapsed = time.monotonic() - start

    output = {
        "schema_version": SCHEMA_VERSION,
        "project": slice_.project,
        "cve": slice_.cve,
        "entrypoints": final_entries,
    }
    report = RunReport(
        project=slice_.project,
        cve=slice_.cve,
        slice_counts=slice_.row_counts(),
        miner_chunks=miner_result.per_chunk,
        candidates_proposed=len(proposed),
        verifier_calls=verifier_calls,
        kept=kept,
        quarantined=quarantined,
        elapsed_sec=elapsed,
    )
    return output, report


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _synthetic_unverified_verdict(error_text: str) -> dict[str, Any]:
    """Build a quarantined-with-failure-reason verdict to substitute
    when the verifier LLM call raised. Shape matches the verifier's
    real output schema closely enough for ``_merge_candidate_verdict``
    to consume it. The fact that this is synthetic is recorded in
    ``quarantine_reason``; downstream Step 3 can detect the
    "verifier unreachable:" prefix and decide whether to re-run.
    Per CLAUDE.md / PLAN Rule 4: silent delete is forbidden — every
    candidate that the miner proposed appears in entrypoints.json,
    even when the verifier could not reach it."""
    return {
        "verdict": "quarantined",
        "reachability": "<verifier unreachable>",
        "attacker_controllability": "<verifier unreachable>",
        "assumptions": [],
        "supporting_substrate_edges": [],
        "refuting_substrate_edges": [],
        "quarantine_reason": f"verifier unreachable: {error_text}"[:600],
        "confidence": "low",
        "uncertainty": (
            "verifier did not return a verdict for this candidate;"
            " status reflects an LLM-call failure, not a substrate"
            " judgement. Downstream steps may re-run."
        ),
    }


def _merge_candidate_verdict(
    candidate: dict[str, Any],
    verdict: dict[str, Any],
) -> dict[str, Any]:
    """Merge a miner candidate with a verifier verdict into a row
    that conforms to ``schemas/entrypoints.v1.json``.

    The merge is information-preserving:
      - structural fields (id, function, file, line, trigger_type,
        trigger_ref) come from the miner.
      - reachability / attacker_controllability / supporting edges /
        confidence / uncertainty come from the *verifier* — the
        verifier had structural facts + substrate evidence and its
        independent reasoning is what downstream layers should
        consume.
      - assumptions / refuting_substrate_edges / quarantine_reason
        come from the verifier (the miner doesn't produce them).
      - status comes from the verdict.
    """
    status = verdict.get("verdict", "quarantined")
    merged: dict[str, Any] = {
        "id": candidate.get("id"),
        "function": candidate.get("function"),
        "file": candidate.get("file"),
        "status": status,
        "trigger_type": candidate.get("trigger_type", "unknown"),
        "confidence": verdict.get("confidence", "low"),
    }
    line = candidate.get("line")
    if line is not None:
        merged["line"] = line
    trigger_ref = candidate.get("trigger_ref")
    if trigger_ref:
        merged["trigger_ref"] = trigger_ref
    if verdict.get("reachability"):
        merged["reachability"] = verdict["reachability"]
    if verdict.get("attacker_controllability"):
        merged["attacker_controllability"] = verdict["attacker_controllability"]
    assumptions = verdict.get("assumptions") or []
    if assumptions:
        merged["assumptions"] = assumptions
    sup = verdict.get("supporting_substrate_edges") or []
    if sup:
        merged["supporting_substrate_edges"] = sup
    ref = verdict.get("refuting_substrate_edges") or []
    if ref:
        merged["refuting_substrate_edges"] = ref
    if status == "quarantined":
        qr = verdict.get("quarantine_reason") or "Verifier marked quarantined."
        merged["quarantine_reason"] = qr
    if verdict.get("uncertainty"):
        merged["uncertainty"] = verdict["uncertainty"]
    return merged


def write_entrypoints(output: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2) + "\n")
