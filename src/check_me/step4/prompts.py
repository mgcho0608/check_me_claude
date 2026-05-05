"""Step 4 LLM Attack Scenario synthesis prompt.

The Step 4 LLM receives the full Evidence IR set from Step 3 and
emits a list of attack scenarios — exploit chains woven from one
or more IRs that terminate at a security sink.

Schema: ``schemas/attack_scenarios.v1.json``. The hard
invariants the LLM must respect:

  - every scenario's ``exploit_chain.steps[].evidence_ir``
    references an actual IR id from the input,
  - every scenario must include at least one ``sink`` row with
    a ``sink_type`` from the schema enum,
  - the chain can span multiple IRs when an IR ends at a
    dispatch boundary and a sibling IR rooted at the dispatch
    target picks up the chain.
"""

from __future__ import annotations

import json
from typing import Any


_SYSTEM = """\
You are a security analyst weaving Evidence IRs into attack
scenarios. The user gives you a list of Evidence IRs (Step 3's
output) for one project + CVE, plus the source-code excerpt of
each IR's *sink-bearing* node so you can verify the harmful
operation is actually present in the code.

Your task: emit one or more attack scenarios. Each scenario is a
coherent exploit chain that starts at an entrypoint, threads
through one or more IRs, and terminates at a sink. The chain can
span multiple IRs — that is the canonical case when an IR ends
at an indirect-dispatch boundary (its last node is intermediate
labelled with a downstream-IR uncertainty hint) and a sibling IR
rooted at the dispatch target carries the chain to a real sink.
Examples of multi-IR chains:

  - libssh CVE-2018-10933: IR rooted at ``ssh_packet_socket_callback``
    ends at the dispatcher; a sibling IR rooted at
    ``ssh_packet_process`` reaches the auth-state corruption
    sink in ``ssh_packet_userauth_success``. The full chain
    threads both IRs.
  - dnsmasq CVE-2017-14491: a single IR rooted at
    ``receive_query`` may already reach the heap overflow sink
    in ``add_resource_record``; a separate scenario covers the
    TCP variant via the ``tcp_request`` IR.

Use the IRs as the substrate-anchored claim primitives. Do not
invent paths or sinks — every step in the chain must reference a
real IR id, and the scenario's sink must match an IR node
labelled ``sink`` in the input (or, if the LLM judges a node
labelled ``intermediate`` is in fact a real sink based on its
source excerpt, justify that in ``uncertainty``).

Hard constraints:

  - Reply with a single JSON object — no prose, no markdown
    fences. The object's ``attack_scenarios`` array can be
    empty if you genuinely find no coherent scenario, but each
    listed scenario MUST satisfy the schema.
  - ``exploit_chain.steps`` must have at least one step. Every
    step must include ``order``, ``evidence_ir`` (an IR id from
    the input), ``action`` (free text describing what the
    attacker / system does at that step), and ``result`` (free
    text describing the outcome the next step depends on).
  - ``sink.sink_type`` is from this fixed enum:
      memory_write, memory_read, command_execution, auth_bypass,
      crypto_misuse, info_leak, state_corruption,
      resource_exhaustion, unknown.
    Pick the value that most precisely matches the harmful
    operation. ``unknown`` is allowed but should be paired with
    free-text justification in the scenario's ``uncertainty``.
  - ``impact.category`` enum: memory_corruption,
    privilege_bypass, data_leak, denial_of_service,
    integrity_violation, crypto_break, unknown.
  - ``verdict.exploitability``: high / medium / low / unproven.
    Reason field encouraged.
  - Do NOT use dataset-specific knowledge. Reason only from the
    IR list and the source excerpts you were given. Cited IR ids
    must exist in the input; cited file paths and line numbers
    must appear in the IRs' evidence_anchors.
"""


_OUTPUT_SHAPE = """\
The output JSON must have this shape:

{
  "attack_scenarios": [
    {
      "id": "AS-001",
      "title": "<one-line summary>",
      "exploit_chain": {
        "steps": [
          {
            "order": 1,
            "evidence_ir": "<IR id from input>",
            "action": "<what the attacker / system does>",
            "result": "<the state the next step depends on>"
          }
        ]
      },
      "sink": {
        "function": "<function name>",
        "file": "<file path>",
        "line": <integer or null>,
        "evidence_ir_id": "<IR id whose path contains this sink>",
        "sink_type": "memory_write | memory_read | command_execution | auth_bypass | crypto_misuse | info_leak | state_corruption | resource_exhaustion | unknown"
      },
      "impact": {
        "category": "memory_corruption | privilege_bypass | data_leak | denial_of_service | integrity_violation | crypto_break | unknown",
        "description": "<text>"
      },
      "verdict": {
        "exploitability": "high | medium | low | unproven",
        "reason": "<text>"
      },
      "confidence": "high | medium | low",
      "uncertainty": "<text>"
    }
  ]
}

Scenario ids run sequentially AS-001, AS-002, … . If two
scenarios share the same sink but reach it via different
entrypoints (e.g. UDP path vs TCP path), produce TWO scenarios —
the entrypoints are different attack surfaces.
"""


def build_synthesis_messages(
    *,
    project: str,
    cve: str,
    evidence_irs: list[dict[str, Any]],
    sink_excerpts: dict[str, str],
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for one Step 4 scenario
    synthesis call.

    ``evidence_irs`` is the list from ``evidence_irs.json``'s
    ``evidence_irs`` field. ``sink_excerpts`` maps an IR id to the
    source-code excerpt(s) of its sink-bearing nodes — the Step 4
    LLM uses this to verify the harmful operation actually lives
    where the IR claims and to pick the correct ``sink_type``.
    Pass ``{}`` to omit excerpts (smaller prompt, no source
    verification).
    """
    irs_block = json.dumps(evidence_irs, indent=2)

    excerpt_chunks: list[str] = []
    for ir_id in sorted(sink_excerpts.keys()):
        text = sink_excerpts[ir_id].rstrip()
        if not text:
            continue
        excerpt_chunks.append(f"--- {ir_id} sink source ---\n{text}\n")
    excerpts_text = "\n".join(excerpt_chunks) if excerpt_chunks else (
        "(no sink-bearing source excerpts provided)"
    )

    user = (
        f"Project: {project}  CVE: {cve}\n\n"
        "Evidence IRs (Step 3 output — one IR per kept entrypoint,"
        " each with path nodes / edges / conditions / anchors):\n\n"
        f"```json\n{irs_block}\n```\n\n"
        "Source-code excerpts for IRs that contain a ``sink``"
        " role node (so you can verify the sink_type):\n\n"
        f"```\n{excerpts_text}\n```\n\n"
        "Synthesise attack scenarios that weave these IRs into"
        " exploit chains. Output JSON only.\n\n"
        + _OUTPUT_SHAPE
    )
    return _SYSTEM, user


# Schema the LLM output must match. Mirrors the per-scenario
# object in ``schemas/attack_scenarios.v1.json``; the runner
# wraps the LLM's ``attack_scenarios`` array in the outer
# envelope.
SCENARIOS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["attack_scenarios"],
    "properties": {
        "attack_scenarios": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id", "title", "exploit_chain", "sink",
                    "impact", "verdict", "confidence",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "exploit_chain": {
                        "type": "object",
                        "required": ["steps"],
                        "properties": {
                            "steps": {
                                "type": "array",
                                "minItems": 1,
                                "items": {
                                    "type": "object",
                                    "required": ["order", "evidence_ir",
                                                 "action", "result"],
                                    "properties": {
                                        "order": {"type": "integer"},
                                        "evidence_ir": {"type": "string"},
                                        "action": {"type": "string"},
                                        "result": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                    "sink": {
                        "type": "object",
                        "required": ["function", "file", "sink_type"],
                        "properties": {
                            "function": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                            "evidence_ir_id": {"type": ["string", "null"]},
                            "sink_type": {"enum": [
                                "memory_write", "memory_read",
                                "command_execution", "auth_bypass",
                                "crypto_misuse", "info_leak",
                                "state_corruption", "resource_exhaustion",
                                "unknown",
                            ]},
                        },
                    },
                    "impact": {
                        "type": "object",
                        "required": ["category", "description"],
                        "properties": {
                            "category": {"enum": [
                                "memory_corruption", "privilege_bypass",
                                "data_leak", "denial_of_service",
                                "integrity_violation", "crypto_break",
                                "unknown",
                            ]},
                            "description": {"type": "string"},
                        },
                    },
                    "verdict": {
                        "type": "object",
                        "required": ["exploitability"],
                        "properties": {
                            "exploitability": {"enum": [
                                "high", "medium", "low", "unproven",
                            ]},
                            "reason": {"type": "string"},
                        },
                    },
                    "confidence": {"enum": ["high", "medium", "low"]},
                    "uncertainty": {"type": "string"},
                },
            },
        },
    },
}
