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
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Run the miner LLM and return the parsed candidate list.

    The returned ``CallResult.parsed`` is a dict with one key,
    ``candidates``, mapped to a list of candidate dicts. Schema is
    enforced by ``chat_json``.
    """
    system, user = build_miner_messages(slice_)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=MINER_OUTPUT_SCHEMA,
        max_retries=max_retries,
        chat_fn=chat_fn,
    )
