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


def _select_per_candidate_edges(
    all_edges: list[dict[str, Any]],
    *,
    candidate_funcs: set[str],
    max_total: int,
) -> list[dict[str, Any]]:
    """Distribute the ``max_total`` budget fairly across candidates.

    The previous behaviour was ``sort by (file, line, caller, callee)
    then truncate``. Sort-then-truncate has a fairness bug: edges are
    grouped by file, so candidates whose definitions live in
    alphabetically-late files (e.g. ``os/net/...`` after
    ``arch/cpu/...``) had their entire neighbourhood dropped while
    early-alphabet candidates kept all theirs. The downstream
    ``slice_for_candidate`` walk then had nothing to traverse for
    those candidates regardless of hop depth.

    Round-robin selection: iterate the sorted candidate list, take
    one edge per candidate per pass (deterministic file/line order
    within each candidate), repeat until the budget is exhausted or
    every candidate has been drained. An edge that touches two
    candidates (caller and callee both in ``candidate_funcs``) is
    kept once and counts for both. Final list is sorted for stable
    serialisation. Project-agnostic: walks substrate fields the
    schema defines.
    """
    sort_key = (
        lambda e: (e.get("file", ""), e.get("line") or 0,
                   e.get("caller", ""), e.get("callee", ""))
    )
    edges_by_cand: dict[str, list[dict[str, Any]]] = {
        c: [] for c in candidate_funcs
    }
    for e in all_edges:
        for endpoint in ("caller", "callee"):
            v = e.get(endpoint)
            if isinstance(v, str) and v in candidate_funcs:
                edges_by_cand[v].append(e)
    for c in edges_by_cand:
        edges_by_cand[c].sort(key=sort_key)

    selected_ids: set[int] = set()
    selected: list[dict[str, Any]] = []
    candidates_sorted = sorted(edges_by_cand.keys())
    indices: dict[str, int] = {c: 0 for c in candidates_sorted}
    drained: set[str] = set()

    while len(selected) < max_total and len(drained) < len(candidates_sorted):
        progressed = False
        for c in candidates_sorted:
            if c in drained or len(selected) >= max_total:
                continue
            edges = edges_by_cand[c]
            i = indices[c]
            while i < len(edges) and id(edges[i]) in selected_ids:
                i += 1
            if i >= len(edges):
                drained.add(c)
                indices[c] = i
                continue
            e = edges[i]
            selected.append(e)
            selected_ids.add(id(e))
            indices[c] = i + 1
            progressed = True
        if not progressed:
            break

    selected.sort(key=sort_key)
    return selected


def slice_substrate(
    substrate: dict[str, Any] | str | Path,
    *,
    max_call_edges: int = 1500,
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
    #    candidate. Edges are distributed across candidates with a
    #    fair quota so no candidate's chain gets dropped wholesale
    #    by an alphabetical sort + truncate (the prior cap behaviour
    #    silently zeroed out evidence for candidates whose files
    #    sort late, e.g. ``os/net/...`` after ``arch/cpu/...``).
    all_edges: list[dict[str, Any]] = list(cats.get("call_graph", []))
    neighbor_edges = _select_per_candidate_edges(
        all_edges,
        candidate_funcs=candidate_funcs,
        max_total=max_call_edges,
    )

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


def _call_neighborhood(
    full: SubstrateSlice,
    *,
    seed_function: str,
    seed_file: str | None,
    hop_depth: int,
) -> set[str]:
    """BFS the call_graph from ``seed_function`` in both directions
    out to ``hop_depth`` and return the set of function names
    reached.

    The seed step (distance 1 from the candidate) honours
    ``seed_file`` for outgoing edges (caller == seed): this
    disambiguates same-name C overloads across translation units
    by anchoring the chain to the seed's actual definition file.
    Inbound edges (callee == seed) are not file-disambiguated — the
    edge's ``file`` field pins the *call site*, not the seed's
    body, and we want every caller regardless of where it lives.

    Subsequent hops (distance 2+) are name-only: the chain has
    already left the seed and the substrate's call_graph names are
    used as identifiers. Multiple overloads sharing a name will be
    over-approximated as one node — acceptable because such
    collisions are rare and the verifier sees the per-candidate
    slice with that conservative shape.

    Project-agnostic: walks substrate fields the schema defines.
    No project name, CVE, or symbol-pattern branching.
    """
    if hop_depth < 1:
        return {seed_function}

    # Hop 1 — file-disambiguated for the outgoing side.
    visited: set[str] = {seed_function}
    frontier: set[str] = set()
    for e in full.call_graph:
        caller = e.get("caller")
        callee = e.get("callee")
        if not isinstance(caller, str) or not isinstance(callee, str):
            continue
        if caller == seed_function:
            if seed_file is not None and e.get("file") != seed_file:
                continue
            frontier.add(callee)
        if callee == seed_function:
            frontier.add(caller)
    frontier.discard(seed_function)
    visited |= frontier

    # Hops 2..N — name-only.
    for _ in range(hop_depth - 1):
        nxt: set[str] = set()
        for e in full.call_graph:
            caller = e.get("caller")
            callee = e.get("callee")
            if not isinstance(caller, str) or not isinstance(callee, str):
                continue
            if caller in frontier:
                nxt.add(callee)
            if callee in frontier:
                nxt.add(caller)
        nxt -= visited
        if not nxt:
            break
        visited |= nxt
        frontier = nxt
    return visited


def slice_for_candidate(
    full: SubstrateSlice,
    *,
    candidate_function: str,
    candidate_file: str | None = None,
    hop_depth: int = 2,
) -> SubstrateSlice:
    """Return a candidate-focused projection of ``full`` for the
    verifier.

    Per PLAN §0 / Rule 2b, the verifier critiques ONE candidate at
    a time. Sending the full project slice on every verifier call is
    wasteful — the verifier's questions ("is this reachable? is the
    attacker in control?") only need substrate evidence about the
    candidate and its near neighbourhood, not the whole project.

    Hop depth: the slice keeps everything reachable from the
    candidate within ``hop_depth`` call-graph hops in either
    direction (BFS). ``hop_depth=2`` matches the depth Step 3
    retrieval uses (PLAN §3, "N=2 hybrid"), giving the verifier the
    same chain visibility — wrapper-style entrypoints whose
    candidate function does not itself touch a syscall but whose
    immediate callees do (a common shape in any layered protocol
    stack: the candidate dispatches into helpers that call
    ``recv``/``read``/etc.) become reachable inside the slice rather
    than appearing to the verifier as evidence-less.

    The focused slice keeps, against the resulting neighbourhood:

    - trust_boundaries rows whose ``function`` is in the
      neighbourhood, plus other trust_boundaries in the candidate's
      file as project-wide context.
    - callback_registrations whose ``callback_function`` or
      ``function`` is in the neighbourhood, plus other rows in the
      candidate's file.
    - call_graph edges where BOTH endpoints are in the
      neighbourhood (i.e. the induced subgraph; this prevents
      leaking 3-hop fragments through a single hop endpoint).
    - guards whose ``function`` is in the neighbourhood.
    - evidence_anchors and config_mode_command_triggers in
      ``candidate_file`` only (small, cheap per-file context;
      file-bound by design, not graph-walked).

    Same-name disambiguation: when ``candidate_file`` is supplied,
    the seed-level call_graph edges are matched on
    ``(caller, file)`` together. Subsequent hops are name-only —
    once the chain leaves the seed, the call_graph identifiers are
    used as substrate keys.

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

    neighborhood = _call_neighborhood(
        full,
        seed_function=candidate_function,
        seed_file=candidate_file,
        hop_depth=hop_depth,
    )

    def _row_in_neighborhood(name: str | None, file: str | None) -> bool:
        """A function-named row is in the focused slice if either:

        (a) the function name is the candidate's AND (when
            ``candidate_file`` is set) the row's file matches —
            same-name overload disambiguation at the seed level,
            consistent with how _call_neighborhood disambiguates
            the seed step;
        (b) the function name is some other member of the
            ``hop_depth``-neighbourhood — name-only is fine here
            because the chain has already left the seed.
        """
        if not isinstance(name, str):
            return False
        if name == candidate_function:
            if candidate_file is None:
                return True
            return file is None or file == candidate_file
        return name in neighborhood

    trust = [
        r for r in full.trust_boundaries
        if _row_in_neighborhood(r.get("function"), r.get("file"))
        or (r.get("function") != candidate_function and same_file(r.get("file")))
    ]
    callbacks = [
        r for r in full.callback_registrations
        if _row_in_neighborhood(r.get("callback_function"), r.get("file"))
        or _row_in_neighborhood(r.get("function"), r.get("file"))
        or (
            r.get("callback_function") != candidate_function
            and r.get("function") != candidate_function
            and same_file(r.get("file"))
        )
    ]
    # Edges among neighbourhood functions form the induced subgraph.
    # The seed-level same-name overload is already filtered out by
    # _call_neighborhood (outgoing edges of the seed are anchored to
    # candidate_file). Edges where the *seed* itself appears with a
    # different file are excluded here too, mirroring that.
    def _edge_seed_file_ok(e: dict[str, Any]) -> bool:
        if candidate_file is None:
            return True
        if e.get("caller") == candidate_function:
            return e.get("file") is None or e.get("file") == candidate_file
        return True

    edges = [
        e for e in full.call_graph
        if e.get("caller") in neighborhood
        and e.get("callee") in neighborhood
        and _edge_seed_file_ok(e)
    ]
    guards = [
        g for g in full.guards
        if _row_in_neighborhood(g.get("function"), g.get("file"))
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
