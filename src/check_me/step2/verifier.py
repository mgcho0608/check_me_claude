"""Verifier — independently critique each entrypoint candidate.

Per PLAN §0 / Rule 2b: the verifier runs in a *fresh* LLM session
and never receives the miner's chain of thought. The runner enforces
this by stripping the miner-only keys from the candidate dict before
calling :func:`verify_one` (see ``prompts.candidate_for_verifier``).
"""

from __future__ import annotations

from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import (
    VERIFIER_OUTPUT_SCHEMA,
    build_verifier_messages,
    candidate_for_verifier,
)
from .substrate_slice import SubstrateSlice


def verify_one(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    candidate: dict[str, Any],
    *,
    max_retries: int = 2,
    max_tokens_ceiling: int = 16384,
    reasoning_effort: str | None = "low",
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Verify a single candidate. ``candidate`` is the miner's full
    candidate dict; this function strips the miner-only keys before
    handing it to the verifier prompt builder.

    ``reasoning_effort`` is set to ``"low"`` for the same reason as
    in the miner — the verifier critiques against a focused
    per-candidate slice and an unbounded thinking budget tends to
    crowd out the visible JSON.
    """
    structural = candidate_for_verifier(candidate)
    system, user = build_verifier_messages(slice_, structural)
    extra: dict[str, Any] = {}
    if reasoning_effort is not None:
        extra["reasoning_effort"] = reasoning_effort
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
