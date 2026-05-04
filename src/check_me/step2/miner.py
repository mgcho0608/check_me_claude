"""Miner — propose entrypoint candidates from a substrate slice."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import MINER_OUTPUT_SCHEMA, build_miner_messages
from .substrate_slice import SubstrateSlice


# Floor for the miner's first-attempt max_tokens budget. The shared
# CHECK_ME_LLM_MAX_TOKENS default (4096) is too tight for the miner
# on real projects: a 14-candidate response with reachability /
# attacker_controllability prose runs ~9-10K tokens of visible JSON
# alone, and Gemini 2.5/3 thinking tokens count against the same
# ceiling. Without a floor, the first attempt always returns
# finish_reason=length and burns one retry. 8192 lets the typical
# response complete on the first try while still respecting any
# higher value the operator set via env (we only raise, never lower).
MIN_MINER_MAX_TOKENS = 8192


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
