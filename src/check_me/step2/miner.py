"""Miner — propose entrypoint candidates from a substrate slice."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import MINER_OUTPUT_SCHEMA, build_miner_messages
from .substrate_slice import SubstrateSlice


# Floor for the miner's first-attempt max_tokens budget. The miner is
# instructed to take the recall side of the proposer/verifier split,
# so a typical response carries 20-40 candidates each with
# reachability / attacker_controllability prose (~400 chars ≈ 100
# tokens of visible JSON per candidate). For very large projects
# (an OS-stack codebase with 200+ candidate functions in the slice)
# the prompt asks for 60-80 candidates — that's ~25K visible tokens
# alone, plus reasoning headroom on thinking models. 32768 is the
# safe first-attempt floor that lets the miner emit the full
# recall set without self-truncating. Operator env values higher
# than the floor are respected; lower values are bumped up.
MIN_MINER_MAX_TOKENS = 32768


def mine(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    *,
    max_retries: int = 2,
    max_tokens_ceiling: int = 65536,
    min_max_tokens: int = MIN_MINER_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Run the miner LLM and return the parsed candidate list.

    The returned ``CallResult.parsed`` is a dict with one key,
    ``candidates``, mapped to a list of candidate dicts. Schema is
    enforced by ``chat_json``.

    ``max_tokens_ceiling`` is 64K because the slice for a large
    project can be ~100K input tokens.

    ``min_max_tokens`` is the first-attempt floor — see
    :data:`MIN_MINER_MAX_TOKENS`. Operator env values higher than the
    floor are respected; lower values are bumped up.

    ``reasoning_effort`` caps how many tokens the model spends on
    internal reasoning before producing the visible JSON. Default
    ``"minimal"``: empirically Gemini's OpenAI-compat exposes only
    this OpenAI-standard knob (the native ``thinking_config`` is
    rejected at the body parser), and ``"low"`` was observed to
    leave thinking effectively unbounded on heavier prompts —
    enough to fill the entire response window before any visible
    output is emitted, producing finish_reason=length in a loop.
    The miner does pattern selection over a structured slice, not
    deep deduction, so ``"minimal"`` does not noticeably hurt
    output quality. Providers that don't recognise the field
    silently ignore it. Nothing here is dataset- or project-specific.
    """
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_miner_messages(slice_)
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


def reasoning_extra(reasoning_effort: str | None) -> dict[str, Any]:
    """Build a ``request.extra`` dict that caps internal-reasoning
    tokens via the OpenAI standard ``reasoning_effort`` field.
    Providers that don't recognise the field silently ignore it.
    Runtime knob, not project-specific."""
    if reasoning_effort is None:
        return {}
    return {"reasoning_effort": reasoning_effort}
