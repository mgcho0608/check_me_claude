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

from ..audit_log import AuditLog
from ..llm.client import ChatRequest, ChatResponse, chat, make_client
from ..llm.config import Config, StepKind, load_config
from . import miner as miner_mod
from . import verifier as verifier_mod
from .substrate_slice import (
    SubstrateSlice,
    slice_for_candidate,
    slice_substrate,
    synthetic_candidates_from_substrate,
)

# Source-excerpt extraction for the verifier slice. Imported from
# Step 3 to keep the retrieval logic centralised: the same N=2
# call-graph + function-body extractor that feeds Step 3's IR
# synthesis now also feeds Step 2's verifier critique. PLAN §6
# Rule 2 / Rule 2b.
try:  # circular-import safe — step3 only imports step1 / llm
    from ..step3.code_excerpt import extract_excerpts as _extract_excerpts
    from ..step3.retrieval import compute_neighborhood as _compute_neighborhood
except Exception:  # pragma: no cover — defensive
    _extract_excerpts = None  # type: ignore[assignment]
    _compute_neighborhood = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "v1"

# Default per-call source-excerpt caps for the verifier. The LLM
# only needs enough body to read the candidate and its immediate
# context; a flat cap keeps the per-call prompt size bounded so
# parallel verifier calls don't unpredictably exceed provider
# context budgets. Numbers are soft ceilings — bigger projects
# stay representative because we round-robin across candidate
# functions before truncating, and the runner falls back to even
# tighter caps on input-budget errors.
DEFAULT_VERIFIER_MAX_SOURCE_EXCERPTS = 12
DEFAULT_VERIFIER_MAX_SOURCE_CHARS = 40000


# --------------------------------------------------------------------------- #
# Verifier-side helpers — input-budget detection, dispatch-context heuristic,
# excerpt capping. Module-level so the test suite can call them directly.
# --------------------------------------------------------------------------- #


def _looks_like_input_budget_error(exc: BaseException) -> bool:
    """True when an LLM error message names the input-token / context-
    length budget being exceeded.

    The strings checked are vendor-published wording snippets that
    do not depend on a specific model or provider — they are the
    surface forms OpenAI / Anthropic / Gemini / vLLM use when the
    request is too large. Generic by construction: no project name
    or symbol is consulted."""
    msg = str(exc).lower()
    return any(
        marker in msg
        for marker in (
            "input tokens exceed",
            "context length",
            "maximum context length",
            "configured limit",
        )
    )


def _needs_richer_dispatch_context(cand: dict[str, Any]) -> bool:
    """True when the candidate's trigger looks like an indirect-
    dispatch handler (callback / event / boot_phase) and the
    verifier needs a wider slice + source posture to chase the
    ingress without tripping over file-locality.

    Generic over substrate categories — looks at ``trigger_type``
    and any ``callback_registrations[`` citation in
    ``supporting_substrate_edges``. No symbol or project pattern."""
    ttype = cand.get("trigger_type", "")
    if ttype in ("callback", "event", "boot_phase"):
        return True
    sup = cand.get("supporting_substrate_edges") or []
    return any(
        isinstance(s, str) and "callback_registrations[" in s for s in sup
    )


def _cap_source_excerpts(
    excerpts: list[Any],
    *,
    candidate_function: str,
    candidate_file: str | None,
    max_functions: int,
    max_chars: int,
) -> list[Any]:
    """Trim source excerpts to a per-call budget.

    Order: candidate's own function-and-file first, then other
    excerpts sorted by ``(file, line)`` so trimming is
    deterministic. ``max_chars`` is computed against each
    excerpt's ``body`` (assumed string-typed); excerpts whose
    body misses are still counted by ``max_functions``. The
    candidate's own excerpt is always kept (we never return an
    empty list when the input was non-empty)."""
    if not excerpts:
        return []
    own: list[Any] = []
    rest: list[Any] = []
    for ex in excerpts:
        fn = getattr(ex, "function", None)
        fl = getattr(ex, "file", None)
        if fn == candidate_function and (
            candidate_file is None or fl == candidate_file
        ):
            own.append(ex)
        else:
            rest.append(ex)
    rest.sort(
        key=lambda ex: (
            getattr(ex, "file", "") or "",
            getattr(ex, "line_start", 0) or 0,
        )
    )
    ordered = own + rest

    kept: list[Any] = []
    char_total = 0
    for ex in ordered:
        if len(kept) >= max_functions:
            break
        body = getattr(ex, "body", "") or ""
        body_len = len(body)
        if kept and char_total + body_len > max_chars:
            break
        kept.append(ex)
        char_total += body_len
    if not kept and ordered:
        kept = [ordered[0]]
    return kept


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
    synthetic_count: int = 0
    discovered_count: int = 0
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
    source_root: Path | None = None,
    miner_config: Config | None = None,
    verifier_config: Config | None = None,
    miner_client: Any | None = None,
    verifier_client: Any | None = None,
    miner_chunk_size: int = miner_mod.DEFAULT_CHUNK_SIZE,
    miner_max_workers: int = miner_mod.DEFAULT_MAX_WORKERS,
    miner_use_chunk_focused_slice: bool = True,
    miner_chunk_hop_depth: int = 1,
    verifier_max_workers: int = 8,
    verifier_retry_passes: int = 2,
    verifier_retry_cooldown_sec: float = 5.0,
    audit_log: AuditLog | None = None,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], RunReport]:
    """Run Step 2 end-to-end (lossless architecture).

    Two streams feed the verifier:

      (1) Deterministic synthetic candidates built directly from
          substrate cuts (anchors + 1-hop closure + call-graph
          roots). The LLM miner does NOT process these — its
          per-candidate enumeration was pure redundancy because
          the verifier is anchoring-blind (PLAN §0 / Rule 2b)
          and ignores miner-side reasoning.
      (2) Discovery-only miner output. The miner is chunked over
          the same pool for substrate-projection size bounding,
          but its task is to propose NEW entrypoints the cuts
          missed (most importantly indexed dispatchers).
          Empty miner output is the common and correct case.

    Both streams merge into one list, are renumbered EP-001 …,
    then each candidate gets an independent verifier critique
    with anchoring prevention.

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

    ``verifier_max_workers`` defaults to ``8`` for the
    internal-LLM environment without per-minute quotas. Raised
    from 4 after a stack-style C project run (several hundred
    candidates, per-candidate average ~2 minutes) showed the
    internal-LLM server tolerated additional concurrency without
    per-request slowdown — total wall-clock halves with 8
    workers when the server is not throughput-bound. On
    public-cloud providers with strict quotas (e.g. per-minute
    input-token caps) drop to 1 to pace under quota. Candidate
    counts can run into the hundreds on stack-style C codebases
    so the retry passes handle transient hiccups regardless.

    Configs and clients are optional — if not supplied, the runner
    loads them from the environment and constructs OpenAI SDK
    clients. Tests pass stubbed values.

    Returns
    -------
    (entrypoints_json, report)
        ``entrypoints_json`` matches ``schemas/entrypoints.v1.json``.
    """
    start = time.monotonic()
    if audit_log is None:
        audit_log = AuditLog.disabled()
    # Materialise the substrate as a dict so source-excerpt retrieval
    # can walk it later without re-reading the file.
    if isinstance(substrate, (str, Path)):
        substrate_dict: dict[str, Any] = json.loads(Path(substrate).read_text())
    elif isinstance(substrate, dict):
        substrate_dict = substrate
    else:  # already a JSON string
        substrate_dict = json.loads(str(substrate))
    slice_ = slice_substrate(substrate_dict)

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

    # libclang warm-up — the first source-excerpt call materialises
    # the libclang index for the project. Doing it once up-front
    # avoids a thundering-herd cold-start when verifier calls run
    # in parallel and several workers race to build the index. A
    # failure here is non-fatal: each per-candidate call retries on
    # its own and logs a warning if it can't extract excerpts.
    if source_root is not None and _extract_excerpts is not None:
        try:
            _extract_excerpts(source_root, [])
        except Exception as warm_exc:  # noqa: BLE001 — non-fatal
            logger.warning(
                "step2: libclang warm-up failed — continuing without"
                " excerpts. err=%s",
                f"{type(warm_exc).__name__}: {warm_exc}"[:200],
            )

    # 1a. Deterministic synthetic candidates --------------------------------
    # Substrate cuts produce a candidate pool the verifier can
    # consume directly. Bypassing the miner on these saves the
    # LLM call cost of per-candidate enumeration, which the
    # verifier ignores anyway (Rule 2b).
    synthetic = synthetic_candidates_from_substrate(substrate_dict)
    logger.info(
        "step2.synthetic: %d substrate-origin candidates (deterministic, "
        "bypass miner)", len(synthetic),
    )

    # 1b. Miner (chunked, parallel) — DISCOVERY only ------------------------
    logger.info("step2.miner: starting on slice %s", slice_.row_counts())
    miner_result = miner_mod.mine_chunked(
        client=miner_client,
        config=miner_config,
        slice_=slice_,
        chunk_size=miner_chunk_size,
        max_workers=miner_max_workers,
        use_chunk_focused_slice=miner_use_chunk_focused_slice,
        chunk_hop_depth=miner_chunk_hop_depth,
        audit_log=audit_log,
        chat_fn=chat_fn,
    )
    discovered: list[dict[str, Any]] = miner_result.parsed.get("candidates", [])
    logger.info(
        "step2.miner: %d chunks -> %d new candidate(s) discovered",
        len(miner_result.per_chunk), len(discovered),
    )

    # 1c. Merge synthetic + discovered, renumber ids globally ---------------
    # Synthetic is dedup'd already (one row per function name);
    # mine_chunked also filters its output against known_candidates.
    # Final dedup by (function, file) protects against a synthetic
    # row whose body file disagreement happens to collide with a
    # discovered row's file (rare; if it occurs we keep the
    # synthetic — it has provenance to a substrate row).
    proposed: list[dict[str, Any]] = []
    seen_keys: set[tuple[str | None, str | None]] = set()
    seen_funcs: set[str] = set()
    for cand in synthetic:
        key = (cand.get("function"), cand.get("file"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        if isinstance(cand.get("function"), str):
            seen_funcs.add(cand["function"])
        proposed.append(cand)
    for cand in discovered:
        fn = cand.get("function")
        if isinstance(fn, str) and fn in seen_funcs:
            continue
        key = (fn, cand.get("file"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        if isinstance(fn, str):
            seen_funcs.add(fn)
        proposed.append(cand)
    proposed.sort(key=lambda c: (c.get("file") or "", c.get("function") or ""))
    for i, cand in enumerate(proposed, 1):
        cand["id"] = f"EP-{i:03d}"
    logger.info(
        "step2: %d total candidate(s) for verifier "
        "(synthetic=%d + discovered=%d)",
        len(proposed), len(synthetic), len(discovered),
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
    # Liveness counter: incremented after every verifier call (success
    # or fail). Logged per-call so a long sequential or parallel run
    # is observable in real time when ``-v`` is on.
    _done = {"n": 0}
    _total = len(proposed)

    def _build_source_excerpts(
        cand: dict[str, Any],
        *,
        hop_depth: int,
        richer: bool,
    ) -> list[Any]:
        """Compute Step-3-style source excerpts for the candidate's
        ``hop_depth`` neighbourhood, capped per the verifier
        budget. ``richer`` widens the cap for callback / event
        handlers whose ingress source-of-truth often sits in a
        cross-file site that the default cap would clip."""
        if (
            source_root is None
            or _compute_neighborhood is None
            or _extract_excerpts is None
        ):
            return []
        try:
            nbhd = _compute_neighborhood(
                substrate_dict,
                entry_function=cand.get("function", ""),
                entry_file=cand.get("file", ""),
                entry_line=cand.get("line"),
                hop_depth=hop_depth,
            )
            targets = [(n.file, n.function) for n in nbhd.nodes if n.file]
            raw = list(_extract_excerpts(source_root, targets))
        except Exception as ex_exc:  # noqa: BLE001
            logger.warning(
                "step2.verifier: source-excerpt extraction failed for"
                " %s(%s) — proceeding without source. err=%s",
                cand.get("id"), cand.get("function"),
                f"{type(ex_exc).__name__}: {ex_exc}"[:200],
            )
            return []
        max_fns = 18 if richer else DEFAULT_VERIFIER_MAX_SOURCE_EXCERPTS
        max_chars = 60000 if richer else DEFAULT_VERIFIER_MAX_SOURCE_CHARS
        return _cap_source_excerpts(
            raw,
            candidate_function=cand.get("function", ""),
            candidate_file=cand.get("file"),
            max_functions=max_fns,
            max_chars=max_chars,
        )

    def _verify_with_context(
        cand: dict[str, Any],
        focused_slice: SubstrateSlice,
        excerpts: list[Any],
    ) -> tuple[Any, float]:
        """Single verifier call with timing. Returns (result, elapsed)."""
        t0 = time.monotonic()
        result = verifier_mod.verify_one(
            client=verifier_client,
            config=verifier_config,
            slice_=focused_slice,
            candidate=cand,
            source_excerpts=excerpts or None,
            chat_fn=chat_fn,
        )
        return result, time.monotonic() - t0

    def _attempt_verify(cand: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Return (cand, verdict, info). info has ``ok: bool`` and
        either ``attempts`` (on success) or ``error`` (on failure).
        On failure a synthetic quarantined verdict is returned so
        the run never partially-fails.

        Multi-tier fallback. The first call uses the default
        per-candidate slice + source excerpts (hop=2 + richer
        caps for callback / event handlers, hop=1 + tighter caps
        otherwise). Two recovery branches:

        1. **Quarantine retry for callback / event candidates.**
           When the first call returns ``quarantined`` AND the
           candidate looks like an indirect-dispatch handler, retry
           with a wider slice (``include_global_trust_boundaries=
           True``, ``hop_depth=3``) and richer source excerpts.
           This is lossless propagation for the quarantine layer
           — a handler whose ingress lives one hop outside the
           default neighbourhood gets a second chance before being
           filed under quarantine.

        2. **Input-budget shrink retry on overflow.** When the LLM
           call raises with a context-length / input-token error,
           shrink the source excerpts (max=1 / 8000 chars) and
           retry. A second overflow narrows further to
           hop_depth=1 + candidate-only source. Only after that
           do we emit the synthetic quarantined verdict.
        """
        function_name = cand.get("function", "")
        candidate_file = cand.get("file")
        richer_dispatch = _needs_richer_dispatch_context(cand)

        focused = slice_for_candidate(
            slice_,
            candidate_function=function_name,
            candidate_file=candidate_file,
            include_global_trust_boundaries=richer_dispatch,
        )
        # The verifier's question is "is this candidate an
        # entrypoint?" — answered by reading the candidate's body
        # and its immediate callers / callees. hop=1 suffices for
        # most candidates; callback/event handlers benefit from
        # hop=2 because the dispatch-resolved indirect edges land
        # one hop further than the registration site.
        excerpts = _build_source_excerpts(
            cand,
            hop_depth=2 if richer_dispatch else 1,
            richer=richer_dispatch,
        )
        try:
            v_result, elapsed = _verify_with_context(cand, focused, excerpts)
        except Exception as exc:  # noqa: BLE001
            err_text = f"{type(exc).__name__}: {exc}"
            if _looks_like_input_budget_error(exc):
                # Tier 1 retry: shrink source.
                shrunk = _cap_source_excerpts(
                    excerpts,
                    candidate_function=function_name,
                    candidate_file=candidate_file,
                    max_functions=1,
                    max_chars=8000,
                )
                logger.info(
                    "step2.verifier: %s(%s) input-budget overflow on first"
                    " attempt — shrinking source to %d excerpt(s) and"
                    " retrying",
                    cand.get("id"), function_name, len(shrunk),
                )
                try:
                    v_result, elapsed = _verify_with_context(
                        cand, focused, shrunk
                    )
                    fallback_label = "source_cap"
                    excerpts = shrunk
                except Exception as exc2:  # noqa: BLE001
                    if _looks_like_input_budget_error(exc2):
                        # Tier 2 retry: hop=1 slice + candidate-only.
                        hop1_focused = slice_for_candidate(
                            slice_,
                            candidate_function=function_name,
                            candidate_file=candidate_file,
                            hop_depth=1,
                            include_global_trust_boundaries=False,
                        )
                        candidate_only = _cap_source_excerpts(
                            excerpts,
                            candidate_function=function_name,
                            candidate_file=candidate_file,
                            max_functions=1,
                            max_chars=8000,
                        )
                        logger.info(
                            "step2.verifier: %s(%s) input-budget overflow"
                            " again — narrowing to hop=1 slice +"
                            " candidate-only source and retrying",
                            cand.get("id"), function_name,
                        )
                        try:
                            v_result, elapsed = _verify_with_context(
                                cand, hop1_focused, candidate_only
                            )
                            fallback_label = "hop1_source_cap"
                            focused = hop1_focused
                            excerpts = candidate_only
                        except Exception as exc3:  # noqa: BLE001
                            return _record_failure(cand, exc3)
                    else:
                        return _record_failure(cand, exc2)
            else:
                return _record_failure(cand, exc)
        else:
            fallback_label = None

        verdict_str = v_result.parsed.get("verdict", "?")

        # Tier-3 (quarantine retry for callback / event handlers):
        # if a richer-dispatch candidate is quarantined on the
        # first pass, broaden the slice (hop=3 + global trust
        # boundaries) and re-attempt. The broader slice often
        # surfaces an ingress site one hop outside the default
        # neighbourhood that flips the verdict honestly.
        if (
            verdict_str == "quarantined"
            and richer_dispatch
            and fallback_label is None
        ):
            wider_focused = slice_for_candidate(
                slice_,
                candidate_function=function_name,
                candidate_file=candidate_file,
                hop_depth=3,
                include_global_trust_boundaries=True,
            )
            wider_excerpts = _build_source_excerpts(
                cand, hop_depth=3, richer=True,
            )
            logger.info(
                "step2.verifier: %s(%s) quarantined on first pass —"
                " retrying with wider dispatch context (hop=3, global"
                " trust boundaries)",
                cand.get("id"), function_name,
            )
            try:
                wider_result, wider_elapsed = _verify_with_context(
                    cand, wider_focused, wider_excerpts
                )
            except Exception as wider_exc:  # noqa: BLE001
                logger.warning(
                    "step2.verifier: %s(%s) wider-context retry failed —"
                    " keeping first-pass quarantine. err=%s",
                    cand.get("id"), function_name,
                    f"{type(wider_exc).__name__}: {wider_exc}"[:120],
                )
            else:
                v_result = wider_result
                elapsed = wider_elapsed
                verdict_str = v_result.parsed.get("verdict", "?")
                fallback_label = "dispatch_context"

        _done["n"] += 1
        logger.info(
            "step2.verifier: %d/%d %s(%s) verdict=%s elapsed=%.1fs"
            " attempts=%d fallback=%s",
            _done["n"], _total,
            cand.get("id"), cand.get("function"),
            verdict_str,
            elapsed, len(v_result.attempts),
            fallback_label or "none",
        )
        audit_log.append({
            "stage": "step2.verifier",
            "candidate_id": cand.get("id"),
            "function": cand.get("function"),
            "file": cand.get("file"),
            "verdict": verdict_str,
            "confidence": v_result.parsed.get("confidence"),
            "reachability": v_result.parsed.get("reachability"),
            "attacker_controllability": v_result.parsed.get("attacker_controllability"),
            "supporting_substrate_edges": v_result.parsed.get("supporting_substrate_edges") or [],
            "refuting_substrate_edges": v_result.parsed.get("refuting_substrate_edges") or [],
            "quarantine_reason": v_result.parsed.get("quarantine_reason", ""),
            "elapsed_sec": round(elapsed, 2),
            "attempts": len(v_result.attempts),
            "fallback": fallback_label or "none",
            "ok": True,
        })
        info: dict[str, Any] = {
            "ok": True,
            "attempts": v_result.attempts,
        }
        if fallback_label is not None:
            info["fallback"] = fallback_label
        return cand, v_result.parsed, info

    def _record_failure(
        cand: dict[str, Any], exc: BaseException
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        err_text = f"{type(exc).__name__}: {exc}"
        _done["n"] += 1
        logger.warning(
            "step2.verifier: %d/%d %s(%s) FAILED err=%s",
            _done["n"], _total,
            cand.get("id"), cand.get("function"),
            err_text[:120],
        )
        audit_log.append({
            "stage": "step2.verifier",
            "candidate_id": cand.get("id"),
            "function": cand.get("function"),
            "file": cand.get("file"),
            "verdict": "<verifier-unreachable>",
            "ok": False,
            "error": err_text[:300],
        })
        synthetic = _synthetic_unverified_verdict(err_text)
        return cand, synthetic, {"ok": False, "error": err_text[:300]}

    # First pass — bounded parallelism (default sequential for verifier).
    logger.info(
        "step2.verifier: first pass — %d candidate(s), max_workers=%d",
        _total, verifier_max_workers,
    )
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
        synthetic_count=len(synthetic),
        discovered_count=len(discovered),
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
