"""Project-agnostic substrate slicing for Step 2 input.

The candidate pool — the set of function names Step 2 will reason
about — is the union of every function name appearing in the
substrate. Step 1's category boundaries (which row is a "trust
boundary", which is a "callback registration") use rule-based
heuristics that are imperfect by design (PLAN §6 Rule 2: "the
substrate promise is same input → same output, not 100% correct").
Using those category labels as a hard gate for the candidate pool
turns a substrate omission into a Step 2 false negative — the
candidate is never seen by the miner or verifier. Instead we trust
Step 1 to enumerate function names accurately, and the verifier
(with source-excerpt access — see ``step2/runner.py``) decides
reachability and attacker-controllability per PLAN §6 Rule 2
("downstream tolerates substrate imperfections") and Rule 2b
("lossless propagation"). The chunked miner already absorbs pool
growth: chunk count scales linearly with the pool, per-chunk cost
stays constant.

The slice keeps:

- every ``trust_boundaries`` row,
- every ``callback_registrations`` row,
- every ``config_mode_command_triggers`` row in a candidate-
  relevant file,
- every ``call_graph`` edge whose caller OR callee is in the
  candidate pool (now effectively every edge, since the pool is
  the union of all named functions),
- every ``guards`` row whose function is in the expanded set,
- every ``evidence_anchors`` row in a candidate-relevant file.

Soft caps trim the long tail per category to keep the slice
JSON-serialisable in a reasonable token budget for downstream
projection. The caps are large enough that the validated dataset
suite (lwip / mbedtls / sudo / dnsmasq / libssh) fits without
trimming.

This slicing is **principled**, not dataset-specific. The same rule
runs unchanged on any C codebase.
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
    max_call_edges: int = 15_000,
    max_guards: int = 2_000,
    max_anchors: int = 2_000,
    max_config_triggers: int = 2_000,
) -> SubstrateSlice:
    """Build a :class:`SubstrateSlice` from a Step 1 substrate.

    Parameters
    ----------
    substrate
        Either a parsed JSON dict, a JSON string, or a path to a
        JSON file. The shape must match ``schemas/substrate.v1.json``.
    max_call_edges, max_guards, max_anchors, max_config_triggers
        Soft caps for the slice. The caps trim the long tail of
        rows after the relevance filter so the JSON serialisation
        is bounded. Defaults are sized to fit the validated dataset
        suite (lwip / mbedtls / sudo / dnsmasq / libssh) without
        trimming; downstream chunked miner and per-candidate
        verifier slices project this further to per-call prompt
        size. Sorting is deterministic so the trimmed set is
        reproducible.

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

    # 1. Candidate pool: union of every function name appearing in
    #    the substrate. See module docstring for the rationale —
    #    Step 1 category labels are imperfect heuristics, so we don't
    #    use them as a hard gate. Walks every category whose schema
    #    defines a function-named field; project-agnostic.
    candidate_funcs: set[str] = set()

    def _add(name: Any) -> None:
        if isinstance(name, str) and name:
            candidate_funcs.add(name)

    for r in trust_rows:
        _add(r.get("function"))
    for r in callback_rows:
        _add(r.get("callback_function"))
        _add(r.get("function"))
    for r in all_config:
        _add(r.get("function"))
    for r in cats.get("call_graph", []):
        _add(r.get("caller"))
        _add(r.get("callee"))
    for r in cats.get("data_control_flow", []):
        _add(r.get("function"))
    for r in cats.get("guards", []):
        _add(r.get("function"))
    for r in cats.get("evidence_anchors", []):
        _add(r.get("function"))

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


# --------------------------------------------------------------------------- #
# Per-chunk focusing (chunked miner)
# --------------------------------------------------------------------------- #


def slice_for_candidate_chunk(
    full: SubstrateSlice,
    *,
    chunk_candidates: list[str],
    hop_depth: int = 2,
) -> SubstrateSlice:
    """Build a chunk-focused projection of ``full`` for the chunked
    miner — generalises :func:`slice_for_candidate` from one
    candidate (verifier) to a chunk's N assigned candidates (miner).

    Why this exists. On large C codebases the full
    :class:`SubstrateSlice` (typical ~1500 call_graph edges + ~900
    callback_registrations + 400 each of guards / anchors / config
    triggers) can run 100-200K LLM tokens before the chunk's
    user-message is added. With ``reasoning_effort: "high"`` and
    visible-output reservation, this exceeds the input budget on
    smaller-context internal models (~262K). Without scoping,
    every per-chunk call rejects with a context-length error and
    the chunked miner cannot run at all on such projects.

    Scoping rules. The projection preserves what each Part of the
    miner prompt actually needs:

      Part A — per-candidate enumeration. The miner needs
      substrate evidence about each assigned candidate's
      reachability and attacker-controllability. The candidate's
      own neighbourhood (call edges + guards + anchors in the
      candidate's files) is what the miner reasons over. Other
      candidates' neighbourhoods are not required for Part A.

      Part B — cross-chunk discovery (indexed-dispatch pattern).
      The miner is told to recognise a function appearing as
      ``caller`` of ``call_graph[kind=indirect]`` edges whose
      ``callee`` set overlaps with ``callback_registrations``.
      So Part B's discovery vocabulary is:
        - all callback_registrations rows (the registered handler
          set), because Part B's claim is "is the callee
          registered as a callback elsewhere?",
        - all indirect call_graph edges originating from any
          chunk-assigned candidate (the dispatch evidence
          itself),
        - all trust_boundaries (cross-cutting attacker-input
          surface; small),
        - all config_mode_command_triggers (mode/CLI gates;
          small).
      These four are kept FULL regardless of chunk membership.

      Bulk reduction comes from scoping ``call_graph[kind=direct]``,
      ``guards`` and ``evidence_anchors`` to the chunk's ``hop_depth``-
      neighbourhood (union of each candidate's BFS over the call
      graph). On contiki-class projects this is the 95% of the
      slice mass that gets trimmed; on libssh-class projects the
      neighbourhood is most of the graph anyway and the projection
      is a no-op-ish 5-10% reduction.

    Project-agnostic. Walks substrate fields the schema defines —
    no project-name or symbol-pattern branching. The same rule
    runs unchanged on any C codebase.

    Potential risk (documented; see PLAN.md Appendix A).
    Aggressively scoping ``call_graph[kind=direct]`` and
    ``guards`` CAN hide cross-cutting context — e.g. a candidate
    is reached only via a direct call from a ``main_loop`` whose
    own body is several hops away. The verifier (one candidate
    at a time, 2-hop hybrid retrieval) is unaffected — the
    per-candidate slice still walks the full call graph. But the
    chunked miner's Part A reasoning could degrade for such
    cases. **Escape hatch:** ``mine_chunked(...,
    use_chunk_focused_slice=False)`` reverts to the un-projected
    behaviour; useful when a project's miner verdict quality is
    suspected to suffer from over-aggressive scoping. If a future
    project hits this, the symptom is "candidate kept by verifier
    on its 2-hop slice but never proposed by miner because Part
    A claimed insufficient evidence" — that's the signal to
    disable the projection for that project.
    """
    chunk_set = set(chunk_candidates)
    if not chunk_set:
        return full

    # Build the hop-depth neighbourhood as the union of each
    # candidate's BFS. seed_file is None at the chunk level — the
    # chunk has many files; per-candidate seed-file disambiguation
    # is the verifier's job. Name-only is acceptable here because
    # any same-name C overload pulled in is filtered downstream by
    # the per-candidate verifier slice.
    neighborhood: set[str] = set(chunk_set)
    for cand in chunk_set:
        neighborhood |= _call_neighborhood(
            full,
            seed_function=cand,
            seed_file=None,
            hop_depth=hop_depth,
        )

    # ---- Part B vocabulary (kept FULL) ---------------------------
    # 1. Indirect call_graph edges originating from chunk
    #    candidates — these ARE the dispatch evidence Part B looks at.
    indirect_from_chunk = [
        e for e in full.call_graph
        if e.get("kind") == "indirect" and e.get("caller") in chunk_set
    ]
    indirect_callees: set[str] = {
        e.get("callee") for e in indirect_from_chunk
        if isinstance(e.get("callee"), str)
    }

    # 2. callback_registrations: keep rows whose handler or
    #    registration site touches the chunk OR Part B's discovery
    #    set. This preserves the dispatch vocabulary while dropping
    #    rows that are entirely off-chunk (a key reduction on
    #    projects with hundreds of unrelated callbacks).
    chunk_callbacks: list[dict[str, Any]] = []
    for c in full.callback_registrations:
        cb = c.get("callback_function")
        fn = c.get("function")
        if (
            (isinstance(cb, str) and (cb in neighborhood or cb in indirect_callees or cb in chunk_set))
            or (isinstance(fn, str) and (fn in neighborhood or fn in chunk_set))
        ):
            chunk_callbacks.append(c)

    # 3. trust_boundaries — kept FULL. Cross-cutting attacker-input
    #    surface; in practice small (tens-to-low-hundreds rows).
    trust = list(full.trust_boundaries)

    # 4. config_mode_command_triggers — kept FULL. Mode/CLI gates;
    #    cross-cutting and pre-capped at slice_substrate level.
    cfg = list(full.config_mode_command_triggers)

    # ---- Bulk reduction (scoped) ---------------------------------
    # Direct call_graph edges scoped to chunk neighbourhood. Indirect
    # edges from chunk candidates are merged in (dedup by id) so
    # Part B sees its evidence regardless of whether the indirect
    # endpoint is in the neighbourhood.
    direct_edges = [
        e for e in full.call_graph
        if e.get("kind") != "indirect"
        and (e.get("caller") in neighborhood or e.get("callee") in neighborhood)
    ]
    seen_edge_ids: set[int] = set()
    chunk_edges: list[dict[str, Any]] = []
    for e in indirect_from_chunk + direct_edges:
        if id(e) in seen_edge_ids:
            continue
        seen_edge_ids.add(id(e))
        chunk_edges.append(e)

    guards = [g for g in full.guards if g.get("function") in neighborhood]

    # evidence_anchors scoped by file — files containing any
    # neighbourhood-relevant row (trust + callbacks + edges +
    # guards). Same rule as slice_substrate's relevant_files
    # filter, applied at chunk granularity.
    relevant_files: set[str] = set()
    for r in trust + chunk_callbacks + chunk_edges + guards:
        f = r.get("file")
        if isinstance(f, str):
            relevant_files.add(f)
    anchors = [
        a for a in full.evidence_anchors
        if a.get("file") in relevant_files
    ]

    return SubstrateSlice(
        project=full.project,
        cve=full.cve,
        # Keep the FULL candidate_functions list visible — Part B
        # may discover entrypoints outside the chunk's assigned
        # subset, and the user message's chunk_block already
        # delimits the chunk's per-Part-A responsibility.
        candidate_functions=list(full.candidate_functions),
        trust_boundaries=trust,
        callback_registrations=chunk_callbacks,
        config_mode_command_triggers=cfg,
        call_graph=chunk_edges,
        guards=guards,
        evidence_anchors=anchors,
    )
