"""Miner and verifier prompt builders for Step 2.

The miner and verifier are intentionally separate prompts so the
verifier never sees the miner's chain of thought (PLAN.md §0,
"anchoring prevention").

Miner role (post per-candidate-redundancy removal):

The deterministic substrate cuts (anchors + 1-hop closure +
call-graph roots — see ``substrate_slice.slice_substrate``) already
produce a candidate pool that the runner forwards to the verifier
as deterministic synthetic rows. The miner therefore does NOT
re-enumerate substrate-origin candidates; it focuses on cross-
substrate DISCOVERY of entrypoints that the deterministic cuts
miss. The most important shape is the indexed-dispatch pattern
(`handlers[wire_byte](args)`-style runtime function-pointer
selection), but other patterns recur — runtime callback
installations, config / mode trigger handlers whose function name
isn't in callback_registrations, etc. The miner reports any
candidate it discovers that is NOT already in the known pool.

Information flow:

    runner   -> deterministic synthetic pool (from substrate cuts)
    miner    <- substrate slice + known candidate names
    miner    -> NEW candidates only (not in known list)
    runner   -> merges synthetic + miner output -> verifier

    verifier <- substrate slice + ONE candidate's STRUCTURAL fields
                 (function/file/line/trigger_type/supporting_edges)
                 + 1-hop source excerpts. Miner reasoning is
                 stripped before it reaches the verifier.
    verifier -> verdict (kept | quarantined) + structured critique.

Prompts are deliberately project-agnostic — they reference the
schema-level vocabulary ("trust_boundaries",
"callback_registrations", …) but never the names of test corpora.
"""

from __future__ import annotations

import json
from typing import Any

from .substrate_slice import SubstrateSlice


# --------------------------------------------------------------------------- #
# Miner
# --------------------------------------------------------------------------- #


_MINER_SYSTEM = """\
You are a security-analysis assistant doing entrypoint DISCOVERY
for a deterministic substrate extractor. The user gives you:

  (1) a JSON "substrate slice" — full project context (trust
      boundaries, callback registrations, configuration triggers,
      call graph slice, guards, evidence anchors);
  (2) a "known candidates" list — function names already produced
      by deterministic substrate cuts (anchors and 1-hop closure
      and call-graph roots). Those are independently being
      verified; your output must NOT contain any of them.

Your task is to find runtime entrypoints that the substrate cuts
miss but the substrate evidence indicates. Empty output is the
common and correct case when nothing new is warranted.

Most important pattern — INDEXED DISPATCH:
  A function selecting a registered handler from a table by
  attacker-controlled bytes (e.g. `handlers[wire_byte](args)`,
  syscall-table dispatch, event-loop fan-out by message type).
  Such a function is reached only by an internal direct call
  from its parent, but it IS an entrypoint because the attacker
  controls the dispatch index. Recognise it as: a function
  appearing as `caller` in several `call_graph` edges of `kind:
  indirect` whose `callee` set overlaps with functions present
  in `callback_registrations`. The dispatcher itself is the new
  entrypoint candidate.

Other patterns where discovery may apply (each is generic to any
C codebase, never project-specific):
  - callbacks installed via runtime APIs whose registration was
    not captured by the AST extractor (look for indirect
    call_graph edges that target functions not in the known
    list);
  - config / mode / command trigger handlers whose function name
    appears in evidence_anchors but not in
    callback_registrations.

For each NEW row you emit, you must:

- name the function and pin its file + (where applicable) line,
- pick a trigger_type from this fixed enum: command, config,
  callback, event, boot_phase, unknown. Use unknown when the
  fit is approximate; explain in trigger_ref text,
- cite at least one supporting substrate row (its category and
  key identifying fields),
- describe reachability — under what runtime conditions is this
  function reached? — and attacker_controllability — to what
  extent can an attacker shape the input by the time it arrives?
- assign a confidence: high | medium | low,
- record uncertainty — what specifically you are unsure about
  and why.

Hard constraints:

- Reply with a single JSON object — no prose, no markdown fences.
- DO NOT emit a row for any function that appears in the known
  candidates list. Those are handled separately; re-emitting them
  is wasted work and will be discarded.
- Empty list is the expected default. Only emit when substrate
  evidence positively supports a new entrypoint claim.
- Do NOT invent file paths or line numbers. Only cite values that
  appear in the substrate slice.
- Do NOT use dataset-specific knowledge. Reason only from the
  substrate slice provided in this conversation.
- A function on the egress / output side (send-only wrappers,
  serialisers writing to a buffer) is NOT an entrypoint — do not
  emit it.
"""

_MINER_OUTPUT_SHAPE = """\
The output JSON must have this shape:

{
  "candidates": [
    {
      "id": "EP-001",
      "function": "<function name — must NOT be in the known list>",
      "file": "<file path from substrate>",
      "line": <integer or null>,
      "trigger_type": "command | config | callback | event | boot_phase | unknown",
      "trigger_ref": "<short free-text — the cited substrate row(s) and what they imply>",
      "reachability": "<text>",
      "attacker_controllability": "<text>",
      "supporting_substrate_edges": [
        "<short citation, e.g. 'call_graph[caller=foo, kind=indirect]'>"
      ],
      "confidence": "high | medium | low",
      "uncertainty": "<text>"
    }
  ]
}

ids run sequentially EP-001, EP-002, … among new discoveries; the
runner globally renumbers when merging with the deterministic
synthetic pool. Use null for line when no substrate row pins one.
Empty list is the expected default.
"""


def build_miner_messages(
    slice_: SubstrateSlice,
    *,
    chunk: list[str] | None = None,
    known_candidates: list[str] | None = None,
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for the discovery miner.

    ``known_candidates`` is the project-wide list of names already
    in the deterministic synthetic pool (anchors + 1-hop closure
    + call-graph roots from substrate cuts). The miner is
    explicitly forbidden from re-emitting these — its job is to
    find new entrypoints the cuts missed (most importantly
    indexed dispatchers). When None, the slice's
    ``candidate_functions`` field is used as the known set.

    ``chunk`` exists for substrate-projection bounding when called
    from ``mine_chunked`` on large projects: the chunk's assigned
    subset informs which substrate rows are kept in the slice
    projection. Even when chunked, ``known_candidates`` should be
    the FULL project pool so the miner doesn't propose a function
    that another chunk already has covered.
    """
    if known_candidates is None:
        known_candidates = list(slice_.candidate_functions)
    known_set = sorted(set(known_candidates))
    known_block_lines = [
        f"Known candidates ({len(known_set)} function names — DO NOT"
        " emit rows for any of these; only emit NEW discoveries):"
    ]
    if known_set:
        known_block_lines.extend(f"- {fn}" for fn in known_set)
    else:
        known_block_lines.append("(empty)")
    known_block = "\n".join(known_block_lines) + "\n\n"

    if chunk is None:
        focus_block = (
            "Substrate-projection focus: full slice (no chunking — "
            "single-call mode).\n\n"
        )
    else:
        formatted = "\n".join(f"- {fn}" for fn in chunk)
        focus_block = (
            f"Substrate-projection focus ({len(chunk)} candidate names —"
            " these are the candidates around which the substrate slice"
            " was projected; they are already in the known list, you"
            " do NOT need to enumerate them):\n"
            f"{formatted}\n\n"
        )
    user = (
        "Substrate slice (Step 1 deterministic extractor output, restricted"
        " to candidate-relevant rows):\n\n"
        f"```json\n{slice_.to_json(indent=2)}\n```\n\n"
        + known_block
        + focus_block
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
edges) AND the same substrate slice the analyst saw, PLUS the
source code of the candidate function and its 2-hop call-graph
neighbourhood. You do NOT see the analyst's reachability or
attacker-controllability text — your critique must be independent.

The substrate is an imperfect heuristic by design (PLAN §6 Rule 2).
A candidate may be missing from ``trust_boundaries`` /
``callback_registrations`` and still be a real entrypoint — read
the source excerpts to corroborate or refute the candidate's
reachability and attacker-controllability when the substrate is
sparse. Conversely, a candidate may sit in a substrate row that
looks suggestive but the source reveals it as a static lookup
table or local-only helper — read the source and trust what it
shows over what the substrate's category label implies.

Your task: produce a structured critique in the form below, then
recommend keep or quarantine.

Critique fields:

- reachability: is this function actually reachable at runtime
  given what the substrate exposes AND what the source shows?
  Cite the specific edges / rows / source lines that support or
  refute reachability.
- attacker_controllability: can an external attacker shape the
  input the function receives? Cite specific trust_boundaries,
  callback_registrations, or source-level evidence (an external
  socket read, an argv parse, a callback dispatched from a
  network handler). Explicit byte parameters are not required:
  for timer / callback / event handlers the attacker-conditioned
  input may be **mutable session / connection / heap state that
  earlier untrusted ingress populated**. Cite the substrate row
  or source excerpt that shows this earlier ingress when relying
  on this form (e.g. a network read elsewhere that writes the
  same buffer / struct field this handler later reads).
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
  substrate slice or the source excerpts contain.
- The default verdict is "quarantined". "kept" carries the burden
  of proof: it requires positive evidence (substrate or source)
  that BOTH
  (a) the function is actually invoked by an untrusted external
  trigger at runtime — not merely that it touches an
  attacker-relevant API in isolation, AND
  (b) the attacker can shape the bytes the function consumes.
  For arg-less timer / callback / event handlers, criterion (b)
  is also satisfied when the source or substrate positively
  shows that earlier untrusted ingress can pre-condition the
  mutable session / connection / heap state the handler acts on
  — cite the ingress site explicitly when leaning on this form.
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
    surface unless the substrate or source shows a network-driven
    caller.
  * functions registered as callbacks whose registration site is
    only reachable behind a debug-only / build-time-disabled
    code path (look for the registration site sitting under a
    matching ifdef in evidence_anchors).
  * functions on the egress / output side (send-only wrappers,
    serialisers writing to a buffer, log emitters).
  * candidates appearing in a struct-of-function-pointers whose
    source reveals a static lookup table (e.g. character-class
    classifier arrays) rather than a runtime dispatch loop.
  * candidates whose reachability is asserted only in prose with
    no supporting substrate row or source excerpt.
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
    *,
    source_excerpts: list[Any] | None = None,
) -> tuple[str, str]:
    """Return ``(system, user)`` prompts for the verifier.

    ``candidate_structural`` is the candidate dict with ONLY the
    fields the verifier is allowed to see. The miner's reachability /
    attacker_controllability / uncertainty prose is stripped by the
    runner before this function is called; this function therefore
    just serialises whatever it gets, trusting the caller. The miner
    keys we strip explicitly are listed in ``_VERIFIER_HIDDEN_KEYS``
    so anyone editing the runner can audit at a glance.

    ``source_excerpts`` is an optional list of
    :class:`step3.code_excerpt.FunctionExcerpt` (duck-typed here as
    ``Any`` to avoid an import cycle); when supplied, the function
    bodies are appended to the user message so the verifier can
    corroborate the substrate with the actual source. This is the
    Step 2 counterpart to Step 3's N=2 retrieval — same posture,
    same depth — and is what allows the verifier to recover
    candidates whose substrate evidence is sparse but whose source
    reveals a real entrypoint (e.g. a public library API, a
    layer-internal dispatch target, or a plugin entry hook
    whose substrate row carries little beyond a function name).
    """
    parts: list[str] = [
        "Substrate slice (Step 1 deterministic extractor output):\n\n"
        f"```json\n{slice_.to_json(indent=2)}\n```\n\n",
        "Entrypoint candidate (structural only — analyst's reasoning"
        " withheld):\n\n"
        f"```json\n{json.dumps(candidate_structural, indent=2)}\n```\n\n",
    ]
    if source_excerpts:
        parts.append(_format_source_excerpts(source_excerpts))
    parts.append(
        "Critique this candidate independently. Output JSON only.\n\n"
        + _VERIFIER_OUTPUT_SHAPE
    )
    return _VERIFIER_SYSTEM, "".join(parts)


def _format_source_excerpts(excerpts: list[Any]) -> str:
    """Render a list of FunctionExcerpt-like objects as a fenced
    code block per function. Each excerpt is duck-typed: it must
    expose ``function``, ``file``, ``line_start``, ``line_end``,
    and ``body`` attributes (matching :class:`step3.code_excerpt.
    FunctionExcerpt`)."""
    lines: list[str] = [
        "Source excerpts of the candidate and its 2-hop call-graph"
        " neighbourhood (use these to corroborate or refute the"
        " substrate's claims about reachability and attacker"
        " controllability — do NOT cite line numbers from the source"
        " excerpt itself in your critique, only substrate rows; the"
        " excerpts are for understanding, not for new evidence"
        " anchors):\n\n"
    ]
    for ex in excerpts:
        header = (
            f"// {ex.file}:{ex.line_start}-{ex.line_end}"
            f"  function: {ex.function}\n"
        )
        lines.append("```c\n" + header + ex.body)
        if not ex.body.endswith("\n"):
            lines.append("\n")
        lines.append("```\n\n")
    return "".join(lines)


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
