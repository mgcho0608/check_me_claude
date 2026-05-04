"""Miner — propose entrypoint candidates from a substrate slice."""

from __future__ import annotations

from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from .prompts import MINER_OUTPUT_SCHEMA, build_miner_messages
from .substrate_slice import SubstrateSlice


def mine(
    client: Any,
    config: Config,
    slice_: SubstrateSlice,
    *,
    max_retries: int = 2,
    max_tokens_ceiling: int = 65536,
    reasoning_effort: str | None = "low",
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Run the miner LLM and return the parsed candidate list.

    The returned ``CallResult.parsed`` is a dict with one key,
    ``candidates``, mapped to a list of candidate dicts. Schema is
    enforced by ``chat_json``.

    ``max_tokens_ceiling`` is 64K because the slice for a large
    project can be ~100K input tokens and Gemini 2.5/3 thinking
    tokens count against the response budget alongside the visible
    JSON output.

    ``reasoning_effort`` is plumbed through ``ChatRequest.extra`` so
    Gemini's OpenAI-compat layer caps its thinking budget. ``"low"``
    is the default — the miner does pattern selection over a
    structured slice, not deep deduction, so an unbounded thinking
    budget mostly squeezes out the visible output. Set ``None`` to
    let the provider pick.
    """
    system, user = build_miner_messages(slice_)
    extra: dict[str, Any] = {}
    if reasoning_effort is not None:
        extra["reasoning_effort"] = reasoning_effort
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
