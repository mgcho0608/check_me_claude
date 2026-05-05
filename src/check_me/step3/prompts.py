"""Step 3 LLM Evidence IR synthesis prompts.

The Step 3 LLM receives:

  - one ``kept`` entrypoint from Step 2 (structural fields plus the
    verifier's reachability / attacker_controllability prose),
  - the deterministic N=2 hybrid neighborhood for that entrypoint
    (call edges + shared-global state co-readers),
  - the source-code excerpt for each function in the neighborhood.

It produces one Evidence IR matching ``schemas/evidence_irs.v1.json``
— nodes (with role: entry / guard / sink / intermediate), edges
(call / dataflow / controlflow / callback / config / state),
required + blocking conditions, and evidence_anchors with explicit
file:line provenance.

Per PLAN §3 the LLM is the *only* synthesis layer; retrieval is
deterministic. The prompt is project-agnostic — it references the
schema's role / edge-kind enums and never names a specific corpus.
"""

from __future__ import annotations

import json
from typing import Any

from ..step3.code_excerpt import FunctionExcerpt
from ..step3.retrieval import Neighborhood


_SYSTEM = """\
You are a security-analysis assistant building an Evidence IR for
a single runtime entrypoint. The Evidence IR is a concrete
execution-path bundle that downstream steps will weave into
attack scenarios. Every claim you produce must trace back to a
file:line citation from the input — never invent a path that the
input does not justify.

The user gives you:

  (1) one runtime entrypoint (function, file, line, trigger_type,
      trigger_ref, plus the upstream verifier's reachability and
      attacker_controllability prose),
  (2) a fixed neighborhood of functions reachable from the
      entrypoint within 2 substrate hops, comprising both
      call-edge hops and shared-global-state co-readers,
  (3) the call-edge / state-edge metadata between those functions,
  (4) the verbatim source code of each function's body.

Your task: produce ONE Evidence IR that connects the entrypoint to
its sinks (or terminates honestly when no sink is reachable in
this neighborhood) by walking the call edges, state edges, and
guards visible in the substrate / source. Specifically:

PART A — Path nodes.

  Pick the functions on a representative execution path through
  the neighborhood, in order from entry to sink. Each node has:

    - function, file, line (cite ONLY values you can see in the
      input; do not invent),
    - role:
        * "entry"        — the starting function (always one node),
        * "intermediate" — function the path passes through,
        * "guard"        — node whose IfStmt / SwitchStmt gates the
                            path (e.g. ``if (state != AUTH) return``),
        * "sink"          — RESERVED. Use only for a node that is
                            actually a security sink: a line that
                            performs the attacker-relevant
                            harmful operation. Concrete examples:
                            unconditional write to security state
                            (``session->session_state = AUTHED``),
                            OOB memory read or write
                            (``buf[attacker_idx]``), free-with-
                            attacker-owned-pointer, command
                            execution (``system(input)``),
                            length confusion that leaks bytes,
                            assertion / abort on attacker-shaped
                            input. Do NOT label the line as
                            ``sink`` merely because the IR's
                            visible neighborhood ends there
                            (e.g. an indirect-callback dispatch
                            site whose target is decided by a
                            registered handler table — that line
                            is a *dispatch boundary*, not a sink).

  Two cases — read carefully:

    Case 1 (the harmful operation IS visible in your source
    excerpts). Label that node ``sink``. Do not punt a real,
    observed sink to "another IR"; if you can see the line that
    writes the corrupted state, frees the dangling pointer,
    indexes out-of-bounds, executes the unchecked command, etc.,
    call it a sink. The whole point of this IR is to surface
    such observations.

    Case 2 (your retrieval neighborhood ends at a boundary that
    does NOT itself contain a harmful operation — typically an
    indirect-callback dispatch site whose target is decided by a
    registered handler table this IR cannot resolve, or the chain
    plausibly continues more than 2 hops away). For that case,
    keep the last reachable node's ``role`` as ``intermediate``
    (or ``guard`` when applicable) and in ``uncertainty``
    explicitly state that the chain continues beyond this IR's
    visible neighborhood, naming the next entrypoint(s) the
    chain could plausibly thread through — typically a function
    in ``callback_registrations`` or a function the indirect
    dispatch resolves into. This signal lets Step 4 weave this
    IR with a sibling IR rooted at that continuation point.

  Concretely: if the source-code excerpts in your input contain
  the harmful operation's text, it goes in this IR as a ``sink``.
  Only when the chain's harmful operation lives outside the
  excerpts you can see should you fall back to Case 2.

  Multiple lines of the same function may appear as separate
  nodes when distinct lines play distinct roles (e.g. one
  intermediate line that dispatches and one sink line that
  writes auth state).

PART B — Path edges.

  Edges connect the nodes you listed. Each edge has from / to
  (matching node identifiers) and a kind from the schema enum:

    - "call"        — a CallExpr edge from the substrate's
                       call_graph
    - "dataflow"    — value flows from one node to the next
                       (parameter passing, struct field, return
                       value, shared-global write→read)
    - "controlflow" — fall-through / jump / branch within a
                       function body (same function, different
                       lines)
    - "callback"    — indirect-dispatch edge (function table,
                       function-pointer assignment, signal
                       handler, struct initializer fp field)
    - "config"      — edge gated by an ``#ifdef`` / build-time
                       feature flag from substrate
                       config_mode_command_triggers
    - "state"       — edge between co-readers/writers of the same
                       global identifier
    - "unknown"     — anything else (use sparingly; explain in
                       uncertainty)

PART C — Conditions.

  - "required": preconditions for the path to fire (build flags,
    deployed configuration, prior packet/handshake state, the
    attacker's choice of input value, registered handler entries
    in callback tables, etc.). Cite substrate or source where
    possible (e.g. "default_packet_handlers[52] ==
    ssh_packet_userauth_success — substrate
    callback_registrations[function_table=default_packet_handlers]
    @ src/packet.c:90").
  - "blocking": runtime conditions that, if added, would block
    the path. The fix in many CVEs is exactly such a check; if
    you can characterise it, do — even when the *vulnerable*
    code lacks it, naming the would-be guard makes the IR
    actionable. Mark such items "Absent in this build —
    introduced by ..." when you can detect that.

PART D — Evidence anchors.

  For every claim in the path, list at least one (file,
  line_start[, line_end], note) anchor pointing at the source
  the LLM saw. Cited line numbers MUST appear in the input. The
  anchors are downstream Step 4's primary citation source.

Output:

  - confidence: high | medium | low — the LLM's subjective
    strength on the path being a real and reachable execution.
  - uncertainty: free text — what specifically would be useful
    to verify, with line numbers when possible.

Hard constraints:

  - Reply with a single JSON object — no prose, no markdown
    fences.
  - Do NOT cite file paths or line numbers that are not present
    in the input. If you cannot find an anchor for a claim, say
    so in uncertainty and weaken confidence.
  - Do NOT use dataset-specific knowledge. Reason only from the
    input substrate slice / source / verifier prose.
  - One Evidence IR per call. Do not aggregate multiple
    entrypoints into a single IR.
  - At minimum: one entry node, evidence_anchors that cover the
    entry node's source location, and an honest confidence
    assessment. A "no path to a sink found in this
    neighborhood" outcome IS valid — set confidence: low,
    explain in uncertainty, leave path.nodes with just the
    entry, and produce an empty path.edges. The IR is still
    useful: Step 4 may chain it via state edges across other
    IRs.
"""


_OUTPUT_SHAPE = """\
The output JSON must have this shape:

{
  "id": "IR-001",
  "entrypoint": {
    "function": "<name>",
    "file": "<file>",
    "line": <integer or null>
  },
  "runtime_context": {
    "trigger_type": "command | config | callback | event | boot_phase | unknown",
    "trigger_ref": "<short text from the entrypoint's trigger_ref or your synthesis>",
    "config_flags": ["<#ifdef flag if any>"]
  },
  "path": {
    "nodes": [
      {"function": "<name>", "file": "<file>", "line": <int|null>,
       "role": "entry|guard|sink|intermediate|unknown"}
    ],
    "edges": [
      {"from": "<node_id>", "to": "<node_id>",
       "kind": "call|dataflow|controlflow|callback|config|state|unknown"}
    ]
  },
  "conditions": {
    "required": ["<text>", "..."],
    "blocking": ["<text>", "..."]
  },
  "evidence_anchors": [
    {"file": "<file>", "line_start": <int>, "line_end": <int|null>,
     "note": "<why this line matters>"}
  ],
  "confidence": "high | medium | low",
  "uncertainty": "<text>"
}

The "id" field is overwritten by the runner with a globally-
sequential identifier (IR-001, IR-002, …); your value is
ignored, but the field must be present so the schema validates.

Node identifiers in the "from"/"to" of edges should be a string
unique to that node — typically "<function>@<line>" — so that
two appearances of the same function at different lines can be
distinguished. The schema does not enforce a specific encoding
for these identifiers; consistency within one IR is what
matters.
"""


def build_synthesis_messages(
    *,
    entrypoint: dict[str, Any],
    neighborhood: Neighborhood,
    excerpts: list[FunctionExcerpt],
    project: str,
    cve: str,
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for one Step 3 IR call.

    ``entrypoint`` is one row from ``entrypoints.v1.json`` (with
    status=kept). ``neighborhood`` is the deterministic retrieval
    result. ``excerpts`` are source-code excerpts for the
    neighborhood's functions, in stable order. ``project`` and
    ``cve`` are echoed back into the user message header for
    operator-side audit logging — they do NOT influence the
    LLM's reasoning beyond identifying which corpus the input
    comes from.
    """
    nbhd_block = json.dumps(neighborhood.to_json(), indent=2)

    excerpt_blocks: list[str] = []
    for ex in excerpts:
        excerpt_blocks.append(
            f"--- {ex.file}:{ex.line_start}-{ex.line_end}  ({ex.function}) ---\n"
            f"{ex.body.rstrip()}\n"
        )
    excerpts_text = "\n".join(excerpt_blocks) if excerpt_blocks else "(no source excerpts)"

    user = (
        f"Project: {project}  CVE: {cve}\n\n"
        "Entrypoint (Step 2 ``kept``, with verifier critique):\n\n"
        f"```json\n{json.dumps(entrypoint, indent=2)}\n```\n\n"
        "Deterministic N=2 hybrid neighborhood for this entrypoint:\n\n"
        f"```json\n{nbhd_block}\n```\n\n"
        "Source-code excerpts for the neighborhood's functions"
        " (verbatim from disk):\n\n"
        f"```\n{excerpts_text}\n```\n\n"
        "Synthesise ONE Evidence IR. Output JSON only.\n\n"
        + _OUTPUT_SHAPE
    )
    return _SYSTEM, user


# JSON schema the synthesis output must validate against. This
# mirrors ``schemas/evidence_irs.v1.json`` for the per-IR object
# (the schema file wraps a list of these in an outer envelope).
IR_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "entrypoint", "runtime_context", "path", "confidence"],
    "properties": {
        "id": {"type": "string"},
        "entrypoint": {
            "type": "object",
            "required": ["function", "file"],
            "properties": {
                "function": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": ["integer", "null"]},
            },
        },
        "runtime_context": {
            "type": "object",
            "required": ["trigger_type"],
            "properties": {
                "trigger_type": {"enum": [
                    "command", "config", "callback", "event",
                    "boot_phase", "unknown",
                ]},
                "trigger_ref": {"type": ["string", "null"]},
                "config_flags": {"type": "array", "items": {"type": "string"}},
            },
        },
        "path": {
            "type": "object",
            "required": ["nodes", "edges"],
            "properties": {
                "nodes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["function", "file", "role"],
                        "properties": {
                            "function": {"type": "string"},
                            "file": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                            "role": {"enum": [
                                "entry", "guard", "sink",
                                "intermediate", "unknown",
                            ]},
                        },
                    },
                },
                "edges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["from", "to", "kind"],
                        "properties": {
                            "from": {"type": "string"},
                            "to": {"type": "string"},
                            "kind": {"enum": [
                                "call", "dataflow", "controlflow",
                                "callback", "config", "state",
                                "unknown",
                            ]},
                        },
                    },
                },
            },
        },
        "conditions": {
            "type": "object",
            "properties": {
                "required": {"type": "array", "items": {"type": "string"}},
                "blocking": {"type": "array", "items": {"type": "string"}},
            },
        },
        "evidence_anchors": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "line_start"],
                "properties": {
                    "file": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": ["integer", "null"]},
                    "note": {"type": "string"},
                },
            },
        },
        "confidence": {"enum": ["high", "medium", "low"]},
        "uncertainty": {"type": "string"},
    },
}
