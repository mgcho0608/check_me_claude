"""Project-agnostic substrate slicing for Step 2 input.

A real project's substrate JSON has too much detail to feed to an
LLM directly: an OS-stack-scale C codebase routinely produces 30k+
data_control_flow rows. The miner only needs the
*candidate-relevant* subset:

- every ``trust_boundaries`` row (every function syntactically
  taking external input is a candidate),
- every ``callback_registrations`` row (every function installed
  under a callback slot is a candidate),
- every ``config_mode_command_triggers`` row (mode/CLI gates),
- ``call_graph`` edges that touch any function appearing in the
  three categories above (one-hop neighborhood) — gives the LLM
  context about how candidates are reached without pulling in the
  whole graph,
- the ``guards`` rows for those neighborhood functions (so the
  miner can reason about preconditions),
- ``evidence_anchors`` rows in files containing the candidate
  functions (lightweight; just the structural artefacts and magic
  values).

This slicing is **principled**, not dataset-specific. The same rule
runs unchanged on any C codebase. The exact tuning point — "one-hop
neighborhood" — is a generic graph operation, documented as such.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Output dataclass
# --------------------------------------------------------------------------- #


@dataclass
class SubstrateSlice:
    """Candidate-relevant subset of a Step 1 substrate.

    All fields are deep-copied JSON-serialisable lists so the slice
    can be passed to ``json.dumps`` and into a chat prompt without
    further processing.

    ``candidate_functions`` is the set of function names the slice
    was built around — every other row in the slice mentions at
    least one of these. The miner uses this set to know what the
    "subject" of the slice is.
    """

    project: str
    cve: str
    candidate_functions: list[str]
    trust_boundaries: list[dict[str, Any]] = field(default_factory=list)
    callback_registrations: list[dict[str, Any]] = field(default_factory=list)
    config_mode_command_triggers: list[dict[str, Any]] = field(default_factory=list)
    call_graph: list[dict[str, Any]] = field(default_factory=list)
    guards: list[dict[str, Any]] = field(default_factory=list)
    evidence_anchors: list[dict[str, Any]] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "cve": self.cve,
            "candidate_functions": list(self.candidate_functions),
            "trust_boundaries": self.trust_boundaries,
            "callback_registrations": self.callback_registrations,
            "config_mode_command_triggers": self.config_mode_command_triggers,
            "call_graph": self.call_graph,
            "guards": self.guards,
            "evidence_anchors": self.evidence_anchors,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent)

    def row_counts(self) -> dict[str, int]:
        return {
            "trust_boundaries": len(self.trust_boundaries),
            "callback_registrations": len(self.callback_registrations),
            "config_mode_command_triggers": len(self.config_mode_command_triggers),
            "call_graph": len(self.call_graph),
            "guards": len(self.guards),
            "evidence_anchors": len(self.evidence_anchors),
            "candidate_functions": len(self.candidate_functions),
        }


# --------------------------------------------------------------------------- #
# Slicing
# --------------------------------------------------------------------------- #


def slice_substrate(
    substrate: dict[str, Any] | str | Path,
    *,
    max_call_edges: int = 800,
    max_guards: int = 400,
    max_anchors: int = 400,
    max_config_triggers: int = 400,
) -> SubstrateSlice:
    """Build a :class:`SubstrateSlice` from a Step 1 substrate.

    Parameters
    ----------
    substrate
        Either a parsed JSON dict, a JSON string, or a path to a
        JSON file. The shape must match ``schemas/substrate.v1.json``.
    max_call_edges, max_guards, max_anchors, max_config_triggers
        Soft caps for the post-relevance-filter slice. The caps
        target a total slice of ~80K LLM tokens so that even
        thinking-token-heavy providers (Gemini 2.5/3) have room
        for the visible JSON response within their output budget.
        Each cap kicks in *after* the candidate-relevance filter,
        so excess rows that no candidate touches were already
        dropped — the cap only trims the long tail of relevant-
        but-redundant rows. Sorting is deterministic
        (file → line → name) so the trimmed set is reproducible.

    Notes
    -----
    The slice contract is *project-agnostic*. The selection rule
    walks substrate categories the schema defines; it does NOT
    branch on project name or specific symbol patterns.
    """
    data = _load(substrate)
    cats = data.get("categories") or {}

    trust_rows: list[dict[str, Any]] = list(cats.get("trust_boundaries", []))
    callback_rows: list[dict[str, Any]] = list(cats.get("callback_registrations", []))
    all_config: list[dict[str, Any]] = list(cats.get("config_mode_command_triggers", []))

    # 1. The core candidate set: every function named in
    #    trust_boundaries (the function field) and every callback_function
    #    in callback_registrations.
    candidate_funcs: set[str] = set()
    for r in trust_rows:
        if isinstance(r.get("function"), str):
            candidate_funcs.add(r["function"])
    for r in callback_rows:
        if isinstance(r.get("callback_function"), str):
            candidate_funcs.add(r["callback_function"])

    # 2. Neighborhood: call_graph edges where caller OR callee is a
    #    candidate. Sorted for determinism then capped.
    all_edges: list[dict[str, Any]] = list(cats.get("call_graph", []))
    neighbor_edges: list[dict[str, Any]] = [
        e
        for e in all_edges
        if e.get("caller") in candidate_funcs or e.get("callee") in candidate_funcs
    ]
    neighbor_edges.sort(key=lambda e: (e.get("file", ""), e.get("line") or 0,
                                        e.get("caller", ""), e.get("callee", "")))
    if len(neighbor_edges) > max_call_edges:
        neighbor_edges = neighbor_edges[:max_call_edges]

    # 3. Expanded function set: candidates + their neighbors.
    expanded_funcs = set(candidate_funcs)
    for e in neighbor_edges:
        if isinstance(e.get("caller"), str):
            expanded_funcs.add(e["caller"])
        if isinstance(e.get("callee"), str):
            expanded_funcs.add(e["callee"])

    # 4. Guards in any function in the expanded set.
    all_guards: list[dict[str, Any]] = list(cats.get("guards", []))
    relevant_guards = [g for g in all_guards if g.get("function") in expanded_funcs]
    relevant_guards.sort(key=lambda g: (g.get("file", ""),
                                          g.get("guard_line") or 0,
                                          g.get("function", "")))
    if len(relevant_guards) > max_guards:
        relevant_guards = relevant_guards[:max_guards]

    # 5. Files containing candidate-relevant rows. config_triggers
    #    and evidence_anchors are filtered by file so the slice
    #    covers candidate context without dumping the whole project.
    relevant_files: set[str] = set()
    for r in trust_rows + callback_rows + neighbor_edges + relevant_guards:
        f = r.get("file")
        if isinstance(f, str):
            relevant_files.add(f)

    # 6. config_mode_command_triggers in files containing
    #    candidate-relevant rows (project-wide enumeration would
    #    swamp the slice on large CMake projects).
    config_rows = [
        c for c in all_config if c.get("file") in relevant_files
    ]
    config_rows.sort(key=lambda c: (c.get("file", ""), c.get("line") or 0,
                                       c.get("name", "")))
    if len(config_rows) > max_config_triggers:
        config_rows = config_rows[:max_config_triggers]

    # 7. Evidence anchors in those same files.
    all_anchors: list[dict[str, Any]] = list(cats.get("evidence_anchors", []))
    relevant_anchors = [
        a for a in all_anchors if a.get("file") in relevant_files
    ]
    relevant_anchors.sort(key=lambda a: (a.get("file", ""), a.get("line") or 0,
                                            a.get("kind", "")))
    if len(relevant_anchors) > max_anchors:
        relevant_anchors = relevant_anchors[:max_anchors]

    return SubstrateSlice(
        project=str(data.get("project", "<unknown>")),
        cve=str(data.get("cve", "<unknown>")),
        candidate_functions=sorted(candidate_funcs),
        trust_boundaries=trust_rows,
        callback_registrations=callback_rows,
        config_mode_command_triggers=config_rows,
        call_graph=neighbor_edges,
        guards=relevant_guards,
        evidence_anchors=relevant_anchors,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _load(substrate: dict | str | Path) -> dict[str, Any]:
    if isinstance(substrate, dict):
        return substrate
    if isinstance(substrate, Path):
        return json.loads(substrate.read_text())
    return json.loads(substrate)


# --------------------------------------------------------------------------- #
# Per-candidate focusing
# --------------------------------------------------------------------------- #


def slice_for_candidate(
    full: SubstrateSlice,
    *,
    candidate_function: str,
    candidate_file: str | None = None,
) -> SubstrateSlice:
    """Return a candidate-focused projection of ``full`` for the
    verifier.

    Per PLAN §0 / Rule 2b, the verifier critiques ONE candidate at
    a time. Sending the full project slice on every verifier call is
    wasteful — the verifier's questions ("is this reachable? is the
    attacker in control?") only need substrate evidence about the
    specific candidate, not the whole project.

    The focused slice keeps:

    - the trust_boundaries row(s) for ``candidate_function`` and (as
      project-wide context) other trust_boundaries in the same file,
    - all callback_registrations whose ``callback_function`` is the
      candidate (these directly refute or support callback-style
      reachability),
    - call_graph edges where caller == candidate or callee ==
      candidate (one-hop in/out),
    - guards in ``candidate_function`` only,
    - evidence_anchors and config_mode_command_triggers in
      ``candidate_file`` only (small, cheap per-file context).

    Same-name disambiguation: when ``candidate_file`` is supplied,
    rows that name the candidate function are matched on
    ``(function, file)`` together. C codebases routinely have
    multiple ``static`` definitions sharing a function name across
    translation units — a high-level API stub in one file and the
    low-level handler with the same name in another is a common
    layering pattern. Without file disambiguation, evidence about
    the unrelated overload leaks into the verifier's slice. Edges'
    ``file`` field pins the *call site*, so caller-side matches are
    file-disambiguated but callee-side matches stay name-only (the
    candidate is already file-identified by its definition; we
    want to see everything it calls regardless of where the call
    happens).

    The selection rule is project-agnostic — it walks substrate
    fields the schema defines, never special-cases a project name
    or symbol pattern.
    """
    if candidate_file is None:
        # Best-effort lookup from the full slice.
        for r in (
            *full.trust_boundaries,
            *full.callback_registrations,
        ):
            if r.get("function") == candidate_function or r.get("callback_function") == candidate_function:
                f = r.get("file")
                if isinstance(f, str):
                    candidate_file = f
                    break

    same_file = (lambda f: f == candidate_file) if candidate_file else (lambda f: False)

    def _is_candidate(row: dict[str, Any], name_field: str) -> bool:
        """Match a row to the candidate by ``(name, file)`` when
        ``candidate_file`` is set, falling back to name-only when it
        isn't. Rows without a ``file`` field still match on name."""
        if row.get(name_field) != candidate_function:
            return False
        if candidate_file is None:
            return True
        rf = row.get("file")
        return rf is None or rf == candidate_file

    trust = [
        r for r in full.trust_boundaries
        if _is_candidate(r, "function")
        or (r.get("function") != candidate_function and same_file(r.get("file")))
    ]
    callbacks = [
        r for r in full.callback_registrations
        if _is_candidate(r, "callback_function")
        or _is_candidate(r, "function")
        or (
            r.get("callback_function") != candidate_function
            and r.get("function") != candidate_function
            and same_file(r.get("file"))
        )
    ]
    edges = [
        e for e in full.call_graph
        if _is_candidate(e, "caller") or e.get("callee") == candidate_function
    ]
    guards = [
        g for g in full.guards
        if _is_candidate(g, "function")
    ]
    anchors = [a for a in full.evidence_anchors if same_file(a.get("file"))]
    cfg = [t for t in full.config_mode_command_triggers if same_file(t.get("file"))]

    return SubstrateSlice(
        project=full.project,
        cve=full.cve,
        candidate_functions=[candidate_function],
        trust_boundaries=trust,
        callback_registrations=callbacks,
        config_mode_command_triggers=cfg,
        call_graph=edges,
        guards=guards,
        evidence_anchors=anchors,
    )
