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
        * "sink"          — node where the bug fires (data corruption,
                            authentication bypass, OOB write/read,
                            assertion of attacker-controlled
                            state, command injection, etc.).

  Multiple lines of the same function may appear as separate
  nodes when distinct lines play distinct roles (e.g. one
  intermediate line that dispatches and one sink line that
  writes auth state).

  IMPORTANT — depth of the sink node. If the source-code excerpts
  in your input contain the body of a callee whose internals
  perform the actual harmful operation (e.g. the call site shows
  ``if (add_resource_record(...))`` and the excerpt for
  ``add_resource_record`` shows its body with the unbounded
  pointer write), put the sink node at the *callee's harmful line*
  inside the callee's file, NOT at the caller's call line. The
  call line is at most an ``intermediate`` node; the harmful line
  inside the called function (its actual write / OOB index /
  command exec / state-corruption assignment) is the ``sink``.
  Add the callee as its own node in your path with the right
  file and line. Going one node deeper is correct when its body
  is in your input; staying at the caller's line is conservative
  and loses precision.

  IMPORTANT — inter-function transition before in-function sinks.
  If the entry function's own body contains a tempting sink-like
  line (an unchecked write, an unguarded dereference, a state
  assignment) AND the substrate neighborhood ALSO exposes
  inter-function call edges leaving the entry function (direct or
  dispatch-resolved indirect — note ``dispatch resolved via
  <table>[]`` on indirect call_graph rows means a function-table
  dispatch was resolved to candidate handlers), prefer to walk at
  least one such inter-function edge whose callee body is in the
  source excerpts before committing to an entry-function-internal
  sink. Real CVE chains usually cross function boundaries; an in-
  entry sink is valid only when the entry function is itself the
  bug-bearing frame (e.g. an inline parser that writes past a
  buffer, or a top-level command handler that flips a privilege
  bit on its own). When in doubt — when both the entry-internal
  line AND a callee body could anchor the sink — choose the
  callee whose body the excerpts show, and emit the entry-
  internal line as ``intermediate``. This is a chain-depth
  incentive, not a hard rule: if the inter-function edges
  available are clearly off-target (logging, unrelated init), an
  entry-internal sink is still the honest choice. Cite the
  reasoning in ``uncertainty`` either way so a re-call can
  recover precision when the substrate added context.

  IMPORTANT — sibling-function disambiguation.
  When the neighborhood contains TWO OR MORE functions whose
  names share a common prefix (e.g. ``foo``, ``foo_path``,
  ``foo_fd`` — or any other ``<base>``, ``<base>_<suffix>``
  cluster), do NOT default to the lexicographically first
  match or to the most-frequently-mentioned sibling. The
  substrate ``call_graph`` edges from the entry, the
  ``data_control_flow`` def_use rows, and the verifier prose
  on the entry candidate tell you which specific sibling the
  chain enters. If the substrate / verifier prose names one
  sibling, that one is the chain target — the others appear
  in the neighborhood only because the retrieval walks call
  graphs by name. When the substrate is silent on which
  sibling, prefer the one whose BODY is in the source
  excerpts AND whose body contains the substrate-cited
  ``guards`` / ``data_control_flow`` rows; the others are
  almost always look-alikes that share an interface, not the
  vulnerable frame. Note this reasoning in ``uncertainty``
  so a deeper retrieval call can correct a wrong pick.
  Project-agnostic: the rule is anchored on substrate row
  presence + source body availability, not on a specific
  symbol or naming scheme.

  IMPORTANT — same-function line drift inside callee bodies.
  Once you have decided which callee body to anchor the sink
  in, the body may itself contain MULTIPLE suspicious lines
  (e.g. a ``memcmp`` at one offset and a ``memcpy`` at
  another, or a ``hmac_finish`` after a ``safer_memcmp``
  earlier in the same function). Prefer the line where the
  substrate's ``guards`` row, the verifier's
  ``attacker_controllability`` prose, or an
  ``evidence_anchor`` note positively names the buggy
  primitive over the FIRST suspicious-looking line the body
  exposes. When several lines are equally plausible, emit
  ALL of them as separate ``sink`` nodes (the schema permits
  multiple sinks per path) — that is honest about a
  multi-sink CVE class rather than force-collapsing into a
  single arbitrary pick. Cite each chosen sink line's
  buggy-primitive evidence in ``evidence_anchors``. Same
  project-agnostic anchor: substrate / verifier prose /
  evidence anchors, not a specific symbol or CVE pattern.

  CRITICAL — sink role REQUIRES a real harmful-operation line.
  A node with ``role: "sink"`` MUST have a non-zero, non-null
  ``line`` field that points to the EXACT source line where the
  harmful operation happens (the unbounded write statement, the
  unguarded dereference, the auth-state assignment, the command
  exec call, etc.). Setting ``line: 0`` or ``line: null`` on a
  sink role is FORBIDDEN — it is not a valid sink anchor; it
  is a "I named a function but cannot point to its harmful
  line" hand-wave. If you reference a function in the
  neighborhood whose BODY is NOT present in the source excerpts
  (so you cannot honestly cite a specific harmful line), then
  EITHER:
    (a) emit that function as ``role: "intermediate"`` with the
        line of the call site that reaches it, NOT as a sink;
        place the chain-end where you DO have body visibility,
        OR
    (b) if no honest sink anchor is reachable from the input,
        omit the sink role entirely (the path may legitimately
        end with intermediate-only nodes), set
        ``confidence: low`` and ``needs_more_context: true``,
        and name the missing callee in ``uncertainty`` so the
        runner can re-call at deeper retrieval depth.

  This rule is project-agnostic: a sink anchor without a real
  line citation is unusable for downstream Step 4 attack-chain
  synthesis regardless of which CVE the IR represents. Honest
  "no sink reachable in this neighborhood" is strictly more
  useful than a fabricated ``line: 0`` sink.

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
    possible (e.g. "dispatch_table[<wire-byte>] resolves to the
    sink-bearing handler — substrate
    callback_registrations[function_table=<table-name>]
    @ <file>:<line>").
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

PART E — Context-sufficiency signal (escalation).

  After walking the input, judge whether the neighborhood
  given is sufficient to anchor the IR with high confidence.
  Set ``needs_more_context: true`` in the output ONLY when at
  least one of the following is concretely missing AND naming
  it in ``uncertainty`` would let a re-call at deeper hops
  resolve the gap:

    - a key callee whose body is referenced in the input but
      whose definition is NOT in the source excerpts (the
      neighborhood stopped one hop short of the harmful line),
    - a state-axis link the substrate suggests (a shared
      global appears in another function's def_use rows) but
      whose body excerpt is not attached, leaving the
      cross-function state interaction unverifiable,
    - the chain clearly continues past a node already in the
      input but the next-hop callee body is absent, so you
      cannot place the sink at its true depth.

  When you set ``needs_more_context: true``, name the missing
  function or state link explicitly in ``uncertainty`` (e.g.
  "callee ``foo`` body absent; sink likely at foo:NN" or
  "state link via ``g_state`` to ``bar`` not visible"). The
  runner will recompute the neighborhood at the next hop depth
  and re-call you with the deeper input. Default is
  ``needs_more_context: false`` — set it sparingly, only when
  you have a concrete missing-anchor to name. Flagging
  unnecessarily wastes budget and discards a valid IR you
  could have finalised.

  Even when you set ``needs_more_context: true``, still emit
  the best IR you can build from the input you have — the
  field is a request for re-call, not a refusal to answer.

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
  "uncertainty": "<text>",
  "needs_more_context": <bool, default false — see Part E>
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
        # Part E — optional escalation signal. The runner reads
        # this field; it is stripped from the persisted IR before
        # writing to disk so the on-disk schema stays clean.
        "needs_more_context": {"type": "boolean"},
    },
}
