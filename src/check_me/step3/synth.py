"""Single-IR LLM synthesis call for Step 3.

One ``synthesise_ir`` call = one entrypoint → one Evidence IR.
The runner orchestrates many such calls (one per ``kept``
entrypoint) with sequential dispatch + per-call failure fallback.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from ..step2.miner import reasoning_extra
from .code_excerpt import FunctionExcerpt
from .prompts import IR_OUTPUT_SCHEMA, build_synthesis_messages
from .retrieval import Neighborhood


# Floor for the synthesis call's max_tokens budget. A typical IR
# response is ~3-6K visible JSON tokens (nodes + edges + conditions
# + evidence_anchors + prose). With reasoning headroom on thinking
# models, 16384 is comfortable for sequential dispatch and avoids
# self-truncation. Operator env values higher than the floor are
# respected.
MIN_SYNTH_MAX_TOKENS = 16384


# Step 3 LLM is a deterministic synthesiser over a fixed
# substrate-derived input. Same input → same IR. Temperature 0.0
# matches the verifier's posture (Step 2 verifier is also temp 0).
DEFAULT_SYNTH_TEMPERATURE: float = 0.0


def synthesise_ir(
    client: Any,
    config: Config,
    *,
    entrypoint: dict[str, Any],
    neighborhood: Neighborhood,
    excerpts: list[FunctionExcerpt],
    project: str,
    cve: str,
    max_retries: int = 2,
    max_tokens_ceiling: int = 65536,
    min_max_tokens: int = MIN_SYNTH_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    temperature: float | None = DEFAULT_SYNTH_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Issue one Evidence IR synthesis call.

    Mirrors the shape of ``step2.miner.mine`` /
    ``step2.verifier.verify_one``: temperature override, max_tokens
    floor, ``reasoning_effort`` default ``"minimal"`` so Gemini-
    family thinking models don't crowd out visible output.
    """
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_synthesis_messages(
        entrypoint=entrypoint,
        neighborhood=neighborhood,
        excerpts=excerpts,
        project=project,
        cve=cve,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=IR_OUTPUT_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )
