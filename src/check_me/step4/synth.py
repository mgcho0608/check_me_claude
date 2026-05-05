"""Single LLM call for Step 4 attack scenario synthesis.

Step 4 is fundamentally a holistic synthesis pass: the LLM sees
all of Step 3's IRs and decides which to weave into chains. One
call typically handles the whole project — IR counts and
per-IR JSON sizes are small (~100-300 IRs of ~600 chars each,
plus optional sink-source excerpts).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from ..step2.miner import reasoning_extra
from .prompts import SCENARIOS_OUTPUT_SCHEMA, build_synthesis_messages


# Floor on first-attempt max_tokens. Step 4 scenarios are
# verbose: each one carries an exploit_chain (~2-6 steps with
# action+result text), a sink object, impact, verdict, and
# uncertainty. Five scenarios at ~800 visible JSON tokens each
# = ~4K visible tokens. With reasoning headroom on thinking
# models, 16384 is comfortable.
MIN_SYNTH_MAX_TOKENS = 16384


# Default temperature. Step 4 is the deterministic-synthesis
# half of the pipeline (Step 3 already did the substrate-walk
# work); same input → same scenarios. 0.0 matches the
# verifier and Step 3 synthesis posture.
DEFAULT_SYNTH_TEMPERATURE: float = 0.0


def synthesise_scenarios(
    client: Any,
    config: Config,
    *,
    evidence_irs: list[dict[str, Any]],
    sink_excerpts: dict[str, str],
    project: str,
    cve: str,
    max_retries: int = 2,
    max_tokens_ceiling: int = 65536,
    min_max_tokens: int = MIN_SYNTH_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    temperature: float | None = DEFAULT_SYNTH_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """One Step 4 LLM call. Returns a ``CallResult`` whose
    ``parsed`` is ``{"attack_scenarios": [...]}``."""
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_synthesis_messages(
        project=project, cve=cve,
        evidence_irs=evidence_irs,
        sink_excerpts=sink_excerpts,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client,
        config=config,
        system=system,
        user=user,
        schema=SCENARIOS_OUTPUT_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )
