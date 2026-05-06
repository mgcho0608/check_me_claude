"""Verifier — independently critique each entrypoint candidate.

Per PLAN §0 / Rule 2b: the verifier runs in a *fresh* LLM session
and never receives the miner's chain of thought. The runner enforces
this by stripping the miner-only keys from the candidate dict before
calling :func:`verify_one` (see ``prompts.candidate_for_verifier``).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .miner import reasoning_extra
from .prompts import (
    VERIFIER_OUTPUT_SCHEMA,
    build_verifier_messages,
    candidate_for_verifier,
)
from .substrate_slice import SubstrateSlice


# Verifier temperature default. The verifier is the rigorous-filter
# half of the proposer/verifier split — same input + same evidence
# should yield the same verdict. Determinism is its core property.
DEFAULT_VERIFIER_TEMPERATURE: float = 0.0


def verify_one(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    candidate: dict[str, Any],
    *,
    source_excerpts: list[Any] | None = None,
    max_retries: int = 2,
    max_tokens_ceiling: int = 32768,
    reasoning_effort: str | None = "high",
    temperature: float | None = DEFAULT_VERIFIER_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Verify a single candidate. ``candidate`` is the miner's full
    candidate dict; this function strips the miner-only keys before
    handing it to the verifier prompt builder.

    ``source_excerpts`` (optional) is a list of
    :class:`step3.code_excerpt.FunctionExcerpt` covering the
    candidate function and its 2-hop call-graph neighbourhood. When
    supplied, the verifier sees the source bodies in addition to
    the substrate slice — this is the Step 2 source-visibility
    upgrade per PLAN §6 Rule 2 (downstream tolerates substrate
    imperfections by reading source).

    ``reasoning_effort`` defaults to ``"high"``.

    ``temperature`` defaults to 0.0 — see
    :data:`DEFAULT_VERIFIER_TEMPERATURE`.
    """
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    structural = candidate_for_verifier(candidate)
    system, user = build_verifier_messages(
        slice_, structural, source_excerpts=source_excerpts,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=VERIFIER_OUTPUT_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )
