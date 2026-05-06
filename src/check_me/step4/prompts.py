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
    empty only when the input contains no IR with a ``sink``
    role node and no plausible cross-IR chain to a sink; in
    every other case it must list at least one scenario.

  - **Coverage rule (do not omit assigned IRs).** The user
    message lists an "Assigned IRs" set. Every IR id in that
    set MUST appear as ``evidence_ir`` in at least one
    scenario's ``exploit_chain``. The same IR may be
    referenced by multiple scenarios (e.g. distinct exploit
    paths that share a final sink); the requirement is that
    no assigned IR is silently dropped from the output. If
    two assigned IRs share the same harmful operation but
    differ in their attack surface (e.g. UDP vs TCP, server
    vs client role, distinct entrypoint families), produce
    a separate scenario for each — they represent different
    attacker-controlled paths and downstream consumers may
    treat them as independent vulnerabilities.

    The full evidence_irs list also contains non-assigned
    IRs (when a chunked run is in progress, other chunks
    cover them). Non-assigned IRs are visible as CONTEXT —
    you may reference them in a multi-IR weave when an
    assigned IR's chain naturally threads through one (e.g.
    an assigned entrypoint IR ends at a dispatcher and a
    non-assigned IR rooted at the dispatched callee carries
    the chain to a sink). Do NOT emit a scenario whose
    primary anchor is a non-assigned IR — that would
    duplicate the chunk that owns it.

    Use the ``uncertainty`` field to record any IR you
    considered but chose not to make primary and why.

  - **Multi-IR weave is the canonical case.** An exploit chain
    that references the SAME ``evidence_ir`` id at every step
    is almost always a sign the chain is incomplete. Real
    exploits cross IR boundaries: an entrypoint IR rooted at
    the network surface (e.g. a packet read or socket
    callback) ends with the chain dispatched into a handler;
    the handler's IR (rooted at the dispatched function) picks
    up the chain and reaches the sink. When the input contains
    one IR with the *attacker entry* and another IR with the
    *harmful operation* on the same global state or shared
    buffer, your scenario's ``exploit_chain.steps`` SHOULD
    weave them — order=1 references the entry-side IR,
    order=2+ references the sink-side IR. Look for these
    weaves explicitly when you start a scenario:

      (a) IR A's ``path.nodes`` ends with ``role:
          intermediate`` whose ``function`` is ALSO present
          in IR B's ``entrypoint`` field — direct dispatch
          weave.
      (b) IR A and IR B share at least one node function
          name or one ``conditions.required`` reference to
          the same global state — state-axis weave.
      (c) IR A's ``runtime_context.trigger_type`` is
          ``callback`` / ``event`` (network-driven) AND
          IR B's path contains a ``role: sink`` node — a
          natural attacker-input → harmful-operation pair.

    A 4-step chain whose ``evidence_ir`` field is the same id
    four times is a SINGLE-IR scenario merely re-numbered as
    multiple steps; this hides path information rather than
    revealing it. Either:
      - weave with another IR (cross-IR ids in steps), OR
      - collapse to a single-step scenario whose ``action``
        and ``result`` describe the chain end-to-end inside
        that one IR.
    The ``uncertainty`` field should note when you tried to
    weave and could not find a partner IR.

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
    assigned_ir_ids: list[str] | None = None,
    chunk_index: int | None = None,
    chunk_total: int | None = None,
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

    ``assigned_ir_ids`` is the list of IR ids THIS call must
    cover (Part A coverage rule). When a chunked run is active,
    only this subset is the call's responsibility; other IRs in
    ``evidence_irs`` are visible as cross-chunk weaving context.
    When ``None``, the runner derives a default — every IR with a
    sink-role node and confidence ``high`` or ``medium`` — which
    matches the original single-call coverage semantics.

    ``chunk_index`` / ``chunk_total`` are diagnostic; if both
    supplied the user message header notes "chunk K of N" so
    operators reading saved prompts can correlate.
    """
    irs_block = json.dumps(evidence_irs, indent=2)

    if assigned_ir_ids is None:
        assigned_ir_ids = _default_assigned_ir_ids(evidence_irs)
    assigned_set = list(dict.fromkeys(assigned_ir_ids))  # dedupe, preserve order
    if assigned_set:
        assigned_block = "Assigned IRs (Part A coverage — emit ≥1 scenario per id):\n" + "\n".join(
            f"- {ir_id}" for ir_id in assigned_set
        ) + "\n\n"
    else:
        assigned_block = (
            "Assigned IRs: (empty — no IR in this chunk requires a"
            " primary scenario; emit only multi-IR weaves whose"
            " primary anchor sits in another chunk's assigned set,"
            " or an empty attack_scenarios array if none apply)\n\n"
        )

    excerpt_chunks: list[str] = []
    for ir_id in sorted(sink_excerpts.keys()):
        text = sink_excerpts[ir_id].rstrip()
        if not text:
            continue
        excerpt_chunks.append(f"--- {ir_id} sink source ---\n{text}\n")
    excerpts_text = "\n".join(excerpt_chunks) if excerpt_chunks else (
        "(no sink-bearing source excerpts provided)"
    )

    chunk_header = ""
    if chunk_index is not None and chunk_total is not None:
        chunk_header = f"Chunk {chunk_index + 1} of {chunk_total}.\n"

    user = (
        f"Project: {project}  CVE: {cve}\n"
        f"{chunk_header}\n"
        "Evidence IRs (Step 3 output — one IR per kept entrypoint,"
        " each with path nodes / edges / conditions / anchors):\n\n"
        f"```json\n{irs_block}\n```\n\n"
        + assigned_block +
        "Source-code excerpts for IRs that contain a ``sink``"
        " role node (so you can verify the sink_type):\n\n"
        f"```\n{excerpts_text}\n```\n\n"
        "Synthesise attack scenarios that weave these IRs into"
        " exploit chains. Output JSON only.\n\n"
        + _OUTPUT_SHAPE
    )
    return _SYSTEM, user


def _default_assigned_ir_ids(evidence_irs: list[dict[str, Any]]) -> list[str]:
    """Single-call default: every IR with a sink-role node and
    confidence ``high`` or ``medium`` is assigned. Mirrors the
    original (pre-chunked) coverage rule so behaviour for callers
    that don't supply an explicit assignment is unchanged."""
    out: list[str] = []
    for ir in evidence_irs:
        ir_id = ir.get("id")
        if not isinstance(ir_id, str):
            continue
        if ir.get("confidence") not in ("high", "medium"):
            continue
        nodes = (ir.get("path") or {}).get("nodes") or []
        if any(n.get("role") == "sink" for n in nodes):
            out.append(ir_id)
    return out


def collect_sink_bearing_ir_ids(
    evidence_irs: list[dict[str, Any]],
    *,
    confidence_floor: tuple[str, ...] = ("high", "medium"),
) -> list[str]:
    """Public helper for the runner to enumerate the set of IRs
    that the chunked Step 4 must distribute across chunks."""
    out: list[str] = []
    for ir in evidence_irs:
        ir_id = ir.get("id")
        if not isinstance(ir_id, str):
            continue
        if ir.get("confidence") not in confidence_floor:
            continue
        nodes = (ir.get("path") or {}).get("nodes") or []
        if any(n.get("role") == "sink" for n in nodes):
            out.append(ir_id)
    return out


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
