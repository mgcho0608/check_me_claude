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
from ..llm.json_call import CallResult
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
    verifier_max_workers: int = miner_mod.DEFAULT_MAX_WORKERS,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], RunReport]:
    """Run Step 2 end-to-end (lossless architecture).

    Step 2's miner is chunked: every function in the substrate
    slice's ``candidate_functions`` is sent through some chunk's
    miner call. Each chunk also carries a discovery instruction so
    the LLM can propose entrypoints outside the candidate set when
    it spots cross-substrate patterns (indexed dispatchers etc.).
    The merged candidate list is then verified — every row receives
    an independent verifier critique with anchoring prevention.
    Both miner chunks and verifier calls run in parallel via a
    bounded thread pool (see ``miner_max_workers`` /
    ``verifier_max_workers``).

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

    # 2. Verifier (parallel) -------------------------------------------------
    # Per PLAN §0 / Rule 2b the verifier critiques ONE candidate at
    # a time on a focused per-candidate sub-slice; the slice walk
    # is a deterministic substrate operation, the verifier call is
    # an LLM critique. Both run independently per candidate, so
    # they parallelise naturally.
    def _verify_one(cand: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], CallResult]:
        focused = slice_for_candidate(
            slice_,
            candidate_function=cand.get("function", ""),
            candidate_file=cand.get("file"),
        )
        v_result = verifier_mod.verify_one(
            client=verifier_client,
            config=verifier_config,
            slice_=focused,
            candidate=cand,
            chat_fn=chat_fn,
        )
        return cand, v_result.parsed, v_result

    final_entries: list[dict[str, Any]] = [None] * len(proposed)  # type: ignore[list-item]
    verifier_calls: list[dict[str, Any]] = [None] * len(proposed)  # type: ignore[list-item]
    kept = 0
    quarantined = 0
    if verifier_max_workers <= 1 or len(proposed) <= 1:
        verdicts = [_verify_one(c) for c in proposed]
    else:
        with ThreadPoolExecutor(max_workers=verifier_max_workers) as ex:
            futs = [(i, ex.submit(_verify_one, c)) for i, c in enumerate(proposed)]
            verdicts_indexed = [(i, f.result()) for i, f in futs]
            verdicts_indexed.sort(key=lambda p: p[0])
            verdicts = [v for _, v in verdicts_indexed]

    for i, (cand, verdict, v_result) in enumerate(verdicts):
        merged = _merge_candidate_verdict(cand, verdict)
        final_entries[i] = merged
        if merged["status"] == "kept":
            kept += 1
        else:
            quarantined += 1
        verifier_calls[i] = {
            "candidate_id": cand.get("id"),
            "verdict": verdict.get("verdict"),
            "attempts": v_result.attempts,
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
