"""Miner and verifier prompt builders for Step 2.

The miner and verifier are intentionally separate prompts so the
verifier never sees the miner's chain of thought (PLAN.md §0,
"anchoring prevention"). Information flow:

    miner   <- substrate slice
    miner   -> structural candidates (function/file/line/trigger_type
                                       + supporting_substrate_edges
                                       + reachability/controllability
                                       text + confidence/uncertainty)

    verifier <- substrate slice + ONE candidate's STRUCTURAL fields
                 (function/file/line/trigger_type/supporting_edges).
                 The miner's reachability / controllability / uncertainty
                 prose is NOT included.
    verifier -> verdict (kept | quarantined) + structured critique
                 (reachability/controllability/assumptions/refuting_edges)
                 + confidence/uncertainty.

The runner then merges the miner's structural fields with the
verifier's verdict to produce ``entrypoints.v1.json``-shaped rows.

Prompts are deliberately project-agnostic — they reference the
schema-level vocabulary ("trust_boundaries", "callback_registrations",
…) but never the names of test corpora.
"""

from __future__ import annotations

import json
from typing import Any

from .substrate_slice import SubstrateSlice


# --------------------------------------------------------------------------- #
# Miner
# --------------------------------------------------------------------------- #


_MINER_SYSTEM = """\
You are a security-analysis assistant doing entrypoint mining for a
deterministic substrate extractor. The user gives you:

  (1) a JSON "substrate slice" — full project context (trust
      boundaries, callback registrations, configuration triggers,
      call graph slice, guards, evidence anchors);
  (2) an "assigned candidates" list — a chunk of function names
      drawn from the slice's `candidate_functions` array. The full
      candidate set is processed across multiple chunks in parallel;
      this call handles only the chunk listed.

Your task has two parts:

PART A — Per-candidate enumeration (the recall guarantee).

  For EVERY function name in the assigned candidates list, emit
  exactly one candidate row. Skipping is NOT permitted. If you
  doubt the entrypoint claim, still emit the row and let
  `confidence: low` + `uncertainty` express the doubt — a
  separate verifier LLM will critique each row independently with
  burden of proof and quarantine weak claims with structured
  refuting_substrate_edges. Picking which candidates "survive" is
  the verifier's job, not yours; your job is to make sure the
  verifier sees every candidate.

  This division of labour is the foundation of Step 2: false
  positives at your layer are recoverable (they land in the
  quarantined bucket), false negatives are NOT — the verifier
  never sees candidates you didn't propose.

PART B — Cross-chunk discovery (the LLM value-add).

  The deterministic substrate extractor (Step 1) emits
  `candidate_functions` from the trust_boundaries and
  callback_registrations categories. There are runtime entrypoints
  it cannot mechanically detect — most importantly the
  indexed-dispatch pattern, where a function selects a registered
  handler from a table by attacker-controlled bytes (e.g.
  `handlers[wire_byte](args)`, syscall-table dispatch, event-loop
  fan-out by message type). Such a function is reached only by an
  internal direct call from its parent, but it IS an entrypoint
  because the attacker controls the dispatch index.

  Recognise the pattern from the substrate as: a function
  appearing as `caller` in several `call_graph` edges of `kind:
  indirect` whose `callee` set overlaps with functions present in
  `callback_registrations`. If you observe such a function (or any
  other plausible entrypoint pattern) NOT already in the assigned
  candidates list, emit a row for it too — propose it with
  `trigger_type: unknown` and `trigger_ref` noting "indexed
  dispatcher over <table-name>" (or whichever pattern applies).
  Discovery instructions apply to every chunk: the merged miner
  output dedupes by (function, file).

  This pattern is generic to any C codebase (protocol parsers,
  syscall tables, event loops, vtables driven by external bytes);
  it is not project-specific.

For each row you must:

- name the function and pin its file + (where applicable) line,
- pick a trigger_type from this fixed enum: command, config,
  callback, event, boot_phase, unknown. If none fits cleanly,
  use unknown and explain why in the trigger_ref text,
- cite at least one supporting substrate row (its category and key
  identifying fields),
- describe reachability — under what runtime conditions is this
  function reached? — and attacker_controllability — to what extent
  can an attacker shape the input by the time it arrives?
- assign a confidence: high | medium | low (this reflects YOUR
  subjective strength on the entrypoint claim),
- record uncertainty — what specifically you are unsure about and
  why.

Hard constraints:

- Reply with a single JSON object — no prose, no markdown fences.
- Do NOT invent file paths or line numbers. Only cite values that
  appear in the substrate slice.
- Do NOT use dataset-specific knowledge. Reason only from the
  substrate slice provided in this conversation.
- A function on the egress / output side (e.g. send-only API
  wrappers, serialisers writing to a buffer) is NOT an
  entrypoint — emit the row anyway with `confidence: low` and
  `trigger_ref` noting the egress reasoning so the verifier can
  quarantine on a clear refutation.
"""

_MINER_OUTPUT_SHAPE = """\
The output JSON must have this shape:

{
  "candidates": [
    {
      "id": "EP-001",
      "function": "<function name from substrate>",
      "file": "<file path from substrate>",
      "line": <integer or null>,
      "trigger_type": "command | config | callback | event | boot_phase | unknown",
      "trigger_ref": "<short free-text — the cited substrate row(s) and what they imply>",
      "reachability": "<text>",
      "attacker_controllability": "<text>",
      "supporting_substrate_edges": [
        "<short citation, e.g. 'trust_boundaries[function=foo]' or 'callback_registrations[callback_function=bar]'>"
      ],
      "confidence": "high | medium | low",
      "uncertainty": "<text>"
    }
  ]
}

ids run sequentially EP-001, EP-002, … . Use null for line when no
substrate row pins one. Empty list is permitted if no candidate is
warranted.
"""


def build_miner_messages(
    slice_: SubstrateSlice,
    *,
    chunk: list[str] | None = None,
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for the miner.

    ``chunk`` is the assigned-candidates list for this miner call —
    a slice of ``slice_.candidate_functions``. The full candidate
    set is processed across multiple chunks (each in a fresh LLM
    session), and the merged output dedupes by ``(function, file)``.
    When ``chunk`` is None, the miner is told to enumerate every
    function in ``candidate_functions``; this is mainly a unit-test
    backwards-compat path. Production runs always supply a chunk.
    """
    if chunk is None:
        chunk_block = (
            "Assigned candidates: every function name in the slice's"
            " ``candidate_functions`` array (no chunking — single-call mode).\n\n"
        )
    else:
        formatted = "\n".join(f"- {fn}" for fn in chunk)
        chunk_block = (
            f"Assigned candidates ({len(chunk)} function names — emit one"
            " row each per Part A; also emit additional rows for any"
            " cross-chunk discoveries per Part B):\n"
            f"{formatted}\n\n"
        )
    user = (
        "Substrate slice (Step 1 deterministic extractor output, restricted"
        " to candidate-relevant rows):\n\n"
        f"```json\n{slice_.to_json(indent=2)}\n```\n\n"
        + chunk_block
        + "Output JSON only.\n\n"
        + _MINER_OUTPUT_SHAPE
    )
    return _MINER_SYSTEM, user


# JSON schema the miner output must match. Used by chat_json's
# retry-on-validation-failure loop.
MINER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id", "function", "file", "trigger_type",
                    "reachability", "attacker_controllability",
                    "supporting_substrate_edges",
                    "confidence", "uncertainty",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "function": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                    "trigger_type": {
                        "enum": [
                            "command", "config", "callback", "event",
                            "boot_phase", "unknown",
                        ],
                    },
                    "trigger_ref": {"type": "string"},
                    "reachability": {"type": "string"},
                    "attacker_controllability": {"type": "string"},
                    "supporting_substrate_edges": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "confidence": {"enum": ["high", "medium", "low"]},
                    "uncertainty": {"type": "string"},
                },
            },
        },
    },
}


# --------------------------------------------------------------------------- #
# Verifier
# --------------------------------------------------------------------------- #


_VERIFIER_SYSTEM = """\
You are a security-analysis verifier. A separate analyst has
produced a runtime entrypoint candidate from a deterministic
substrate slice. You receive ONLY the candidate's structural facts
(function name, file, line, trigger_type, supporting substrate
edges) AND the same substrate slice the analyst saw. You do NOT see
the analyst's reachability or attacker-controllability text — your
critique must be independent.

Your task: produce a structured critique in the form below, then
recommend keep or quarantine.

Critique fields:

- reachability: is this function actually reachable at runtime
  given what the substrate exposes? Cite the specific edges /
  rows that support or refute reachability.
- attacker_controllability: can an external attacker shape the
  input the function receives? Cite specific trust_boundaries or
  callback_registrations rows.
- assumptions: what runtime conditions must hold for this
  candidate to fire? (build-config flags, deployed configuration,
  mode flags, an open listener, an established session, etc.)
- supporting_substrate_edges: substrate citations consistent with
  the candidate.
- refuting_substrate_edges: substrate citations that argue against
  the candidate. Empty list is fine.
- verdict: "kept" if the candidate stands up to the critique;
  "quarantined" otherwise.
- quarantine_reason: required when verdict is "quarantined".
- confidence: high | medium | low.
- uncertainty: text.

Hard constraints:

- Reply with a single JSON object — no prose, no markdown fences.
- Do not invent file paths or line numbers; cite only what the
  substrate slice contains.
- The default verdict is "quarantined". "kept" carries the burden
  of proof: it requires positive substrate evidence that BOTH
  (a) the function is actually invoked by an untrusted external
  trigger at runtime — not merely that it touches an
  attacker-relevant API in isolation, AND
  (b) the attacker can shape the bytes the function consumes.
  Absence of refuting evidence is NOT sufficient — speculative
  reachability or speculative controllability means quarantine.
  False positives in the kept bucket pollute downstream Step 3;
  false negatives in quarantine are recoverable from audit. PLAN §6
  Rule 4.

- Quarantine, in particular, these common false-positive shapes
  (all generic — they recur in any C codebase, not specific to
  any project in our corpus):
  * functions that read files / env vars / stdin but whose only
    callers are local administration paths (config-file parsers,
    key/cert loaders, CLI password prompts). These are trust
    boundaries to a local attacker, but not the network attack
    surface unless the substrate shows a network-driven caller.
  * functions registered as callbacks whose registration site is
    only reachable behind a debug-only / build-time-disabled
    code path (look for the registration site sitting under a
    matching ifdef in evidence_anchors).
  * functions on the egress / output side (send-only wrappers,
    serialisers writing to a buffer, log emitters).
  * candidates whose reachability is asserted only in prose with
    no supporting substrate row.
"""

_VERIFIER_OUTPUT_SHAPE = """\
The output JSON must have this shape:

{
  "verdict": "kept" | "quarantined",
  "reachability": "<text>",
  "attacker_controllability": "<text>",
  "assumptions": ["<text>", "..."],
  "supporting_substrate_edges": ["<citation>", "..."],
  "refuting_substrate_edges": ["<citation>", "..."],
  "quarantine_reason": "<text or empty if kept>",
  "confidence": "high | medium | low",
  "uncertainty": "<text>"
}
"""


def build_verifier_messages(
    slice_: SubstrateSlice,
    candidate_structural: dict[str, Any],
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for the verifier.

    ``candidate_structural`` is the candidate dict with ONLY the
    fields the verifier is allowed to see. The miner's reachability /
    attacker_controllability / uncertainty prose is stripped by the
    runner before this function is called; this function therefore
    just serialises whatever it gets, trusting the caller. The miner
    keys we strip explicitly are listed in ``_VERIFIER_HIDDEN_KEYS``
    so anyone editing the runner can audit at a glance.
    """
    user = (
        "Substrate slice (Step 1 deterministic extractor output):\n\n"
        f"```json\n{slice_.to_json(indent=2)}\n```\n\n"
        "Entrypoint candidate (structural only — analyst's reasoning"
        " withheld):\n\n"
        f"```json\n{json.dumps(candidate_structural, indent=2)}\n```\n\n"
        "Critique this candidate independently. Output JSON only.\n\n"
        + _VERIFIER_OUTPUT_SHAPE
    )
    return _VERIFIER_SYSTEM, user


VERIFIER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "verdict", "reachability", "attacker_controllability",
        "assumptions", "supporting_substrate_edges",
        "refuting_substrate_edges",
        "confidence", "uncertainty",
    ],
    "properties": {
        "verdict": {"enum": ["kept", "quarantined"]},
        "reachability": {"type": "string"},
        "attacker_controllability": {"type": "string"},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "supporting_substrate_edges": {
            "type": "array", "items": {"type": "string"},
        },
        "refuting_substrate_edges": {
            "type": "array", "items": {"type": "string"},
        },
        "quarantine_reason": {"type": "string"},
        "confidence": {"enum": ["high", "medium", "low"]},
        "uncertainty": {"type": "string"},
    },
}


# Keys on the miner candidate that must NOT travel to the verifier
# (they would leak the miner's chain of thought and defeat the
# anchoring-prevention rule).
_VERIFIER_HIDDEN_KEYS: tuple[str, ...] = (
    "reachability",
    "attacker_controllability",
    "uncertainty",
)


def candidate_for_verifier(
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Strip miner-only fields from a candidate before handing it
    to the verifier. Pure projection — the original dict is
    untouched.
    """
    return {
        k: v
        for k, v in candidate.items()
        if k not in _VERIFIER_HIDDEN_KEYS
    }
