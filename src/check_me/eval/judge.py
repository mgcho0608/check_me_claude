"""Shared LLM judge for Step 3/4 semantic equivalence evaluation.

The judge answers one question for a (gold, ours) pair:

  "Does ``ours`` describe the same vulnerability / execution path
   as ``gold``?"

It returns a structured verdict {same | partial | different} +
free-text reason. Used by both the Step 3 IR matcher (where the
LLM compares execution paths) and the Step 4 attack-scenario
matcher (where the LLM compares exploit chains and impact).

Project-agnostic: the prompt cites the schemas' enum vocabulary
and never names a corpus.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from ..llm.json_call import chat_json, CallResult
from ..step2.miner import reasoning_extra


# Output schema for the judge call.
JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["verdict", "confidence"],
    "properties": {
        "verdict": {"enum": ["same", "partial", "different"]},
        "confidence": {"enum": ["high", "medium", "low"]},
        "reason": {"type": "string"},
        "matched_aspects": {
            "type": "array",
            "items": {"type": "string"},
        },
        "diverging_aspects": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
}


_SYSTEM = """\
You are an evaluator comparing a gold-labelled artefact (an
Evidence IR or an attack scenario) to a pipeline-produced
artefact of the same kind, both for the same project + CVE. Your
task: judge whether the two describe the same underlying
vulnerability or execution path.

Verdicts:

  - "same"      — the two artefacts describe the same execution
                   path / same vulnerability. Minor differences
                   in line numbers, intermediate function picks,
                   or wording are tolerated as long as the
                   structural skeleton is the same: same entry
                   point family (callback / event / command /
                   config trigger), same sink concept, same
                   harmful operation.
  - "partial"   — overlap exists (same entry family OR same
                   sink, but not both; or the path covers part
                   of the gold chain but stops short of the
                   gold sink). State which aspect matches and
                   which diverges in ``matched_aspects`` /
                   ``diverging_aspects``.
  - "different" — the two artefacts describe distinct
                   vulnerabilities or unrelated execution paths.

Output a single JSON object with verdict + confidence
(high/medium/low) + free-text reason. Optionally list specific
matched_aspects and diverging_aspects as short bullets.

Hard constraints:

  - Reply with ONE JSON object only — no prose, no markdown.
  - Do not invent details. Reason only from the two artefacts
    you were given.
  - Do not penalise wording differences if the structural
    skeleton matches. The pipeline's LLM may pick a different
    intermediate function on the same chain or cite a sink line
    that's a few lines away from gold's; treat those as "same"
    when the chain otherwise aligns.
  - Do not use dataset-specific knowledge.
"""


_OUTPUT_SHAPE = """\
{
  "verdict": "same | partial | different",
  "confidence": "high | medium | low",
  "reason": "<text>",
  "matched_aspects": ["<text>", "..."],
  "diverging_aspects": ["<text>", "..."]
}
"""


def build_judge_messages(
    *,
    artefact_kind: str,
    project: str,
    cve: str,
    gold: dict[str, Any],
    ours: dict[str, Any],
) -> tuple[str, str]:
    """``artefact_kind`` is a free-text label like
    ``"Evidence IR"`` or ``"attack scenario"`` so the judge knows
    the schema-level shape it's looking at."""
    user = (
        f"Artefact kind: {artefact_kind}.\n"
        f"Project: {project}  CVE: {cve}\n\n"
        "GOLD artefact:\n"
        f"```json\n{json.dumps(gold, indent=2)}\n```\n\n"
        "OURS artefact (pipeline output, candidate match):\n"
        f"```json\n{json.dumps(ours, indent=2)}\n```\n\n"
        "Judge whether ours describes the same underlying"
        " vulnerability / path as gold. Output JSON only.\n\n"
        + _OUTPUT_SHAPE
    )
    return _SYSTEM, user


# Defaults mirror the verifier's posture (Step 2): temperature=0
# for reproducibility, minimal reasoning_effort to keep the
# judge call cheap.
DEFAULT_JUDGE_TEMPERATURE: float = 0.0
MIN_JUDGE_MAX_TOKENS = 4096


def judge_pair(
    client: Any,
    config: Config,
    *,
    artefact_kind: str,
    project: str,
    cve: str,
    gold: dict[str, Any],
    ours: dict[str, Any],
    max_retries: int = 2,
    max_tokens_ceiling: int = 16384,
    min_max_tokens: int = MIN_JUDGE_MAX_TOKENS,
    reasoning_effort: str | None = "minimal",
    temperature: float | None = DEFAULT_JUDGE_TEMPERATURE,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """One judge call. Returns ``CallResult`` whose ``parsed`` is
    a dict matching :data:`JUDGE_SCHEMA`."""
    if temperature is not None and temperature != config.temperature:
        config = replace(config, temperature=temperature)
    if config.max_tokens < min_max_tokens:
        config = replace(config, max_tokens=min_max_tokens)
    system, user = build_judge_messages(
        artefact_kind=artefact_kind,
        project=project, cve=cve,
        gold=gold, ours=ours,
    )
    extra = reasoning_extra(reasoning_effort)
    return chat_json(
        client=client, config=config,
        system=system, user=user,
        schema=JUDGE_SCHEMA,
        max_retries=max_retries,
        max_tokens_ceiling=max_tokens_ceiling,
        extra_request=extra or None,
        chat_fn=chat_fn,
    )
