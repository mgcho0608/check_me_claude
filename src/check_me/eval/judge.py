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

Verdicts (apply the rubric BEFORE writing the verdict — the
rubric's quantitative criteria override loose intuition):

  - "same"      — ALL of the following hold:
                  (a) same entry-point family AND attack
                      surface (e.g. both are server-side UDP
                      DNS receive; client-side TCP is NOT the
                      same surface as server-side UDP even if
                      both reach the same sink),
                  (b) same sink: ``sink.function`` matches
                      AND ``sink.file`` matches AND
                      ``sink.line`` is within ±5 lines of
                      gold's (a tighter window than "anywhere
                      in the same function"),
                  (c) same harmful operation category
                      (memory_write vs memory_read vs
                      auth_bypass vs state_corruption — these
                      are NOT interchangeable),
                  (d) same impact category and exploitability
                      tier (high/medium/low — within one tier
                      is OK, but ``unproven`` vs ``high`` is
                      NOT same).

  - "partial"   — overlap exists but at least one of (a)/(b)/
                  (c)/(d) above fails. The most common partial
                  shape: gold and ours share the same sink
                  function but reach it from different attack
                  surfaces (e.g. UDP vs TCP variant of the
                  same CVE), or share the same entry surface
                  but ours stops at an intermediate frame
                  before the gold sink. State the failed
                  axis explicitly in ``diverging_aspects`` —
                  e.g. ``"sink.line off by 217 (gold:1082,
                  ours:1065 — function start, not harmful op)"``,
                  ``"attack surface differs: gold UDP, ours
                  TCP"``, ``"sink_type differs: gold
                  memory_write, ours state_corruption"``.

  - "different" — the two artefacts describe distinct
                   vulnerabilities or unrelated execution paths
                   (different sink function, different impact
                   category, or chains that share only a
                   high-level CVE label but no concrete code
                   path).

Output a single JSON object with verdict + confidence
(high/medium/low) + free-text reason. Optionally list specific
matched_aspects and diverging_aspects as short bullets — but
when verdict is ``partial``, ``diverging_aspects`` is REQUIRED
(a partial verdict without a concrete diverging axis is the
hand-wave the rubric is designed to prevent).

Hard constraints:

  - Reply with ONE JSON object only — no prose, no markdown.
  - Do not invent details. Reason only from the two artefacts
    you were given.
  - Do NOT collapse different attack surfaces (UDP vs TCP,
    server vs client, network vs local) into ``same`` even
    when the sink function matches — the attack surface IS
    part of the vulnerability identity. Use ``partial`` and
    name the surface difference in ``diverging_aspects``.
  - Do NOT verdict ``same`` when ``sink.line`` is more than
    ±5 lines from gold's, or when gold's sink line is a real
    integer and ours is ``0``/``null`` (an unanchored sink is
    NOT the same as an anchored one — the line citation IS
    part of the artefact's identity for downstream
    consumers).
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
    max_tokens_ceiling: int = 32768,
    min_max_tokens: int = MIN_JUDGE_MAX_TOKENS,
    reasoning_effort: str | None = "high",
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
