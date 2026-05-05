"""Deterministic N=2 hybrid retrieval for Step 3.

Given a Step 1 substrate and a single Step 2 ``kept`` entrypoint,
compute the set of functions whose code the LLM should see when
synthesising the entrypoint's Evidence IR. Per PLAN §3 the rule is:

    "Retrieval 정책: LLM이 볼 수 있는 코드 범위는 substrate edge 기반
     N-hop neighborhood로 결정론적으로 자름 (LLM 자유 선택 금지),
     N=2로 구현."

Two axes feed the same neighborhood set:

  Axis A — call edges. BFS in the substrate's ``call_graph`` from
  the entrypoint, in BOTH directions, to depth ``hop_depth`` (2 by
  default). The seed step is anchored to the entrypoint's
  ``(function, file)`` so same-name C overloads across translation
  units don't pollute the slice.

  Axis B — shared global state. From the entrypoint and its hop-1
  call-graph neighbours, collect every top-level identifier they
  reference (via ``data_control_flow`` def_use entries — the only
  Step 1 category that records identifier-level usage inside a
  function body). Every other function in the substrate that
  references at least one of those identifiers joins the
  neighborhood. This is how a chain like
  ``process_thread_tcpip_process → tcpip_input → uip_input →
  uip_process`` recovers ``uip_process`` even though no call_graph
  edge spans more than 2 hops to it: ``uip_buf`` / ``uip_len`` co-
  readers form the bridging axis.

Output: a :class:`Neighborhood` of nodes (with role hint:
``entry`` / ``call_neighbour`` / ``state_neighbour``) and edges
(call edges from substrate; ``state`` edges synthesised between
co-readers of a shared identifier).

Project-agnostic: the retrieval walks substrate categories the
schema defines. No project name, no symbol pattern, no LLM.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

# Default hop depth — PLAN §3 fixes this at N=2 hybrid.
DEFAULT_HOP_DEPTH = 2

# Soft caps on the neighborhood size. The LLM synthesis call's
# input budget is bounded by the function-body source we attach
# downstream; clamping the node count here keeps the prompt fitting
# in the model's context. The caps kick in only after the
# substrate-relevance filter runs, so they trim the long tail of
# weakly-connected nodes rather than dropping the candidate's
# direct neighbourhood.
DEFAULT_MAX_NODES = 60
DEFAULT_MAX_STATE_NEIGHBOURS = 30


@dataclass(frozen=True)
class NeighborhoodNode:
    """A function included in the neighborhood. ``role`` is a soft
    structural hint; the LLM ultimately decides each node's IR role
    (entry / guard / sink / intermediate) from the source code.
    ``hop`` is the BFS distance from the seed (0 for the seed,
    1 for direct callers/callees, 2 for two-step neighbours, and
    a sentinel for state-axis-only nodes — see
    :data:`STATE_HOP_SENTINEL`)."""
    function: str
    file: str
    line: int | None
    role: str  # one of: entry, call_neighbour, state_neighbour
    hop: int = 0
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "function": self.function,
            "file": self.file,
            "role": self.role,
            "hop": self.hop,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.note:
            d["note"] = self.note
        return d


# Sentinel "hop" value for nodes that joined the neighborhood
# only via the shared-global-state axis. They sort after all
# call-axis nodes but before the cap.
STATE_HOP_SENTINEL = 99


@dataclass(frozen=True)
class NeighborhoodEdge:
    """A substrate edge between two nodes in the neighborhood.

    ``kind``:
      - ``call_direct`` / ``call_indirect`` — from substrate call_graph
      - ``call_callback`` / ``call_virtual`` — same source, kept
        distinct so the LLM can reason about indirect dispatch
      - ``state`` — synthesised by the retrieval: both endpoints
        reference the same top-level identifier in their bodies.
        The shared identifier name is in ``ref``.
    """
    src: str  # function name (file disambiguates only at the seed)
    dst: str
    kind: str
    file: str | None = None
    line: int | None = None
    ref: str | None = None  # the shared identifier name for state edges

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "from": self.src,
            "to": self.dst,
            "kind": self.kind,
        }
        if self.file is not None:
            d["file"] = self.file
        if self.line is not None:
            d["line"] = self.line
        if self.ref is not None:
            d["ref"] = self.ref
        return d


@dataclass
class Neighborhood:
    """Result of a Step 3 retrieval call. ``entry`` is the seed
    entrypoint; ``nodes`` always contains it as the first item with
    role=``entry``."""
    entry: NeighborhoodNode
    nodes: list[NeighborhoodNode] = field(default_factory=list)
    edges: list[NeighborhoodEdge] = field(default_factory=list)
    shared_globals: list[str] = field(default_factory=list)
    truncated: bool = False
    truncation_note: str = ""

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "entry": self.entry.to_json(),
            "nodes": [n.to_json() for n in self.nodes],
            "edges": [e.to_json() for e in self.edges],
            "shared_globals": list(self.shared_globals),
        }
        if self.truncated:
            d["truncated"] = True
            d["truncation_note"] = self.truncation_note
        return d


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #


def compute_neighborhood(
    substrate: dict[str, Any],
    *,
    entry_function: str,
    entry_file: str,
    entry_line: int | None = None,
    hop_depth: int = DEFAULT_HOP_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_state_neighbours: int = DEFAULT_MAX_STATE_NEIGHBOURS,
) -> Neighborhood:
    """Compute the N=2 hybrid neighborhood for a single entrypoint.

    ``substrate`` is the raw ``substrate.v1.json`` dict (unsliced).
    The retrieval walks the substrate's ``call_graph`` and
    ``data_control_flow`` categories.

    The seed step is file-anchored: outgoing edges of the entry are
    matched on ``(caller, file)`` so a different translation unit's
    same-name overload is not pulled in. Subsequent hops are name-
    only — the chain has left the seed and the substrate's name is
    the substrate-level key.

    State axis: from the entry and its hop-1 call neighbours, gather
    every identifier referenced (def_use rows). Every other
    function whose body references at least one of those
    identifiers joins the neighborhood as a ``state_neighbour``.
    The capped output preserves a representative subset; the
    truncation flag is recorded.
    """
    cats = substrate.get("categories", {}) or {}
    call_graph: list[dict[str, Any]] = list(cats.get("call_graph", []))
    dcf: list[dict[str, Any]] = list(cats.get("data_control_flow", []))

    # 1. Build the entry node.
    entry_node = NeighborhoodNode(
        function=entry_function,
        file=entry_file,
        line=entry_line,
        role="entry",
        note="step2 entrypoint",
    )

    # 2. Axis A — call_graph BFS, file-anchored at the seed step.
    call_nodes, call_edges = _call_neighbourhood(
        call_graph,
        seed_function=entry_function,
        seed_file=entry_file,
        hop_depth=hop_depth,
    )

    # 3. Axis B — shared global state via def_use across the
    #    entry + hop-1 call neighbours.
    hop1_funcs: set[str] = {entry_function}
    for e in call_graph:
        caller = e.get("caller")
        callee = e.get("callee")
        if not isinstance(caller, str) or not isinstance(callee, str):
            continue
        if caller == entry_function and (
            entry_file is None or e.get("file") == entry_file
        ):
            hop1_funcs.add(callee)
        if callee == entry_function:
            hop1_funcs.add(caller)

    state_neighbours, shared_idents, state_edges = _state_neighbourhood(
        dcf,
        seed_funcs=hop1_funcs,
        max_state_neighbours=max_state_neighbours,
    )

    # 4. Merge — entry first, then call-axis nodes, then state-only.
    nodes: list[NeighborhoodNode] = [entry_node]
    seen: set[tuple[str, str]] = {(entry_function, entry_file)}
    for n in call_nodes:
        if n.function == entry_function and n.file == entry_file:
            continue
        key = (n.function, n.file)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(n)
    for n in state_neighbours:
        key = (n.function, n.file)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(n)

    # 5. Sort by (hop, file, function) so the cap below trims the
    #    far tail (high-hop / state-only) first and preserves the
    #    seed-adjacent chain. The seed itself has hop=0 and stays
    #    first.
    nodes.sort(key=lambda n: (n.hop, n.file, n.function))

    # 6. Cap.
    truncated = False
    truncation_note = ""
    if len(nodes) > max_nodes:
        # Distribution by hop tier helps the truncation note
        # describe what was kept vs trimmed.
        from collections import Counter
        hop_counts = Counter(n.hop for n in nodes)
        nodes = nodes[:max_nodes]
        kept_max_hop = max(n.hop for n in nodes)
        truncated = True
        truncation_note = (
            f"cap reached at {max_nodes} nodes (raw {sum(hop_counts.values())});"
            f" kept up to hop {kept_max_hop};"
            f" hop-tier counts {dict(hop_counts)}"
        )

    in_set = {(n.function, n.file) for n in nodes}

    # 7. Filter edges to those whose endpoints are both in the kept set.
    final_edges: list[NeighborhoodEdge] = []
    for e in call_edges:
        if not _edge_endpoints_in(in_set, e):
            continue
        final_edges.append(e)
    for e in state_edges:
        if not _edge_endpoints_in(in_set, e):
            continue
        final_edges.append(e)

    return Neighborhood(
        entry=entry_node,
        nodes=nodes,
        edges=final_edges,
        shared_globals=sorted(shared_idents),
        truncated=truncated,
        truncation_note=truncation_note,
    )


# --------------------------------------------------------------------------- #
# Axis A — call_graph BFS
# --------------------------------------------------------------------------- #


_CALL_KIND_MAP = {
    "direct": "call_direct",
    "indirect": "call_indirect",
    "virtual": "call_virtual",
    "callback": "call_callback",
}


def _call_neighbourhood(
    call_graph: list[dict[str, Any]],
    *,
    seed_function: str,
    seed_file: str,
    hop_depth: int,
) -> tuple[list[NeighborhoodNode], list[NeighborhoodEdge]]:
    """BFS the call_graph from the seed in both directions to
    ``hop_depth``. Seed-step outgoing edges are anchored to
    ``seed_file`` so same-name C overloads across translation units
    are excluded; subsequent hops match by name.

    Returns (nodes, edges). Nodes are role=``call_neighbour``
    (entry-itself excluded — that one is added by the caller). Edges
    carry the substrate kind (``call_direct`` / ``call_indirect`` /
    etc.) plus the call-site ``(file, line)`` for the LLM to cite.
    """
    visited: set[str] = {seed_function}
    visited_files: dict[str, str | None] = {seed_function: seed_file}
    visited_hop: dict[str, int] = {seed_function: 0}
    edges_out: list[NeighborhoodEdge] = []
    frontier: set[str] = {seed_function}

    if hop_depth < 1:
        return [], []

    # Hop 1 — file-anchored on outgoing seed edges.
    next_frontier: set[str] = set()
    for e in call_graph:
        caller = e.get("caller")
        callee = e.get("callee")
        if not isinstance(caller, str) or not isinstance(callee, str):
            continue
        edge_kind = _CALL_KIND_MAP.get(e.get("kind", ""), "call_direct")
        edge_file = e.get("file") if isinstance(e.get("file"), str) else None
        edge_line = e.get("line") if isinstance(e.get("line"), int) else None

        if caller == seed_function:
            if seed_file is not None and edge_file != seed_file:
                continue
            edges_out.append(NeighborhoodEdge(
                src=caller, dst=callee, kind=edge_kind,
                file=edge_file, line=edge_line,
            ))
            if callee not in visited:
                next_frontier.add(callee)
                visited_files.setdefault(callee, edge_file)
                visited_hop.setdefault(callee, 1)
        elif callee == seed_function:
            edges_out.append(NeighborhoodEdge(
                src=caller, dst=callee, kind=edge_kind,
                file=edge_file, line=edge_line,
            ))
            if caller not in visited:
                next_frontier.add(caller)
                visited_files.setdefault(caller, edge_file)
                visited_hop.setdefault(caller, 1)
    visited |= next_frontier
    frontier = next_frontier

    # Hops 2..N — name-only.
    for hop_step in range(2, hop_depth + 1):
        nxt: set[str] = set()
        for e in call_graph:
            caller = e.get("caller")
            callee = e.get("callee")
            if not isinstance(caller, str) or not isinstance(callee, str):
                continue
            edge_kind = _CALL_KIND_MAP.get(e.get("kind", ""), "call_direct")
            edge_file = e.get("file") if isinstance(e.get("file"), str) else None
            edge_line = e.get("line") if isinstance(e.get("line"), int) else None

            if caller in frontier and callee not in visited:
                edges_out.append(NeighborhoodEdge(
                    src=caller, dst=callee, kind=edge_kind,
                    file=edge_file, line=edge_line,
                ))
                nxt.add(callee)
                visited_files.setdefault(callee, edge_file)
                visited_hop.setdefault(callee, hop_step)
            if callee in frontier and caller not in visited:
                edges_out.append(NeighborhoodEdge(
                    src=caller, dst=callee, kind=edge_kind,
                    file=edge_file, line=edge_line,
                ))
                nxt.add(caller)
                visited_files.setdefault(caller, edge_file)
                visited_hop.setdefault(caller, hop_step)
            # Edges between two already-visited nodes (excluding the
            # seed; its edges were emitted in hop 1) describe the
            # chain inside the neighborhood — keep them too.
            if (
                caller in visited and callee in visited
                and caller != seed_function and callee != seed_function
            ):
                key = (caller, callee, edge_file, edge_line)
                if not any(
                    (oe.src, oe.dst, oe.file, oe.line) == key for oe in edges_out
                ):
                    edges_out.append(NeighborhoodEdge(
                        src=caller, dst=callee, kind=edge_kind,
                        file=edge_file, line=edge_line,
                    ))
        nxt -= visited
        if not nxt:
            break
        visited |= nxt
        frontier = nxt

    nodes_out: list[NeighborhoodNode] = []
    for fn in sorted(visited):
        if fn == seed_function:
            continue
        nodes_out.append(NeighborhoodNode(
            function=fn,
            file=visited_files.get(fn) or "",
            line=None,
            role="call_neighbour",
            hop=visited_hop.get(fn, hop_depth),
        ))
    # Sort by (hop, file, function): closer-to-seed first so the
    # downstream cap protects the chain rather than alphabetical
    # luck. Within a hop tier, file/function for determinism.
    nodes_out.sort(key=lambda n: (n.hop, n.file, n.function))
    edges_out.sort(key=lambda e: (e.file or "", e.line or 0, e.src, e.dst, e.kind))
    return nodes_out, edges_out


# --------------------------------------------------------------------------- #
# Axis B — shared global state via data_control_flow def_use
# --------------------------------------------------------------------------- #


def _state_neighbourhood(
    dcf: list[dict[str, Any]],
    *,
    seed_funcs: set[str],
    max_state_neighbours: int,
) -> tuple[list[NeighborhoodNode], set[str], list[NeighborhoodEdge]]:
    """Find functions that share top-level identifier references
    with the seed set.

    The substrate's ``data_control_flow`` rows include def_use
    entries that name the identifier and the function. We collect:

      1. Identifiers referenced by any function in ``seed_funcs``
         (via def_use rows where the row's function is in seed).
      2. Other functions that reference any of those identifiers.

    Returns (state_neighbour nodes, set of shared identifiers,
    synthetic ``state`` edges between co-readers).
    """
    # Map identifier -> set of (function, file)
    by_ident: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for r in dcf:
        if r.get("kind") != "def_use":
            continue
        fn = r.get("function")
        file = r.get("file")
        if not isinstance(fn, str) or not isinstance(file, str):
            continue
        # The substrate records the identifier name in either
        # ``ref`` (newer rows) or extracted from ``summary`` (older
        # rows). Try ref first, then fall back to summary parsing.
        ident = r.get("ref")
        if not isinstance(ident, str) or not ident:
            ident = _extract_identifier_from_summary(r.get("summary", ""))
        if not isinstance(ident, str) or not ident:
            continue
        by_ident[ident].add((fn, file))

    # 1. Seeds' identifiers.
    seed_idents: set[str] = set()
    for ident, users in by_ident.items():
        for fn, _f in users:
            if fn in seed_funcs:
                seed_idents.add(ident)
                break

    # 2. Co-readers — functions referencing any seed identifier.
    co_readers: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ident in seed_idents:
        for fn, file in by_ident.get(ident, set()):
            if fn in seed_funcs:
                continue
            co_readers[(fn, file)].add(ident)

    # 3. Sort + cap. Sort by (file, function) for determinism.
    sorted_co = sorted(co_readers.items(), key=lambda p: (p[0][1], p[0][0]))
    if len(sorted_co) > max_state_neighbours:
        sorted_co = sorted_co[:max_state_neighbours]

    state_nodes: list[NeighborhoodNode] = []
    state_edges: list[NeighborhoodEdge] = []
    for (fn, file), idents in sorted_co:
        sample = ", ".join(sorted(idents)[:3])
        extra = "" if len(idents) <= 3 else f" (+{len(idents)-3} more)"
        state_nodes.append(NeighborhoodNode(
            function=fn,
            file=file,
            line=None,
            role="state_neighbour",
            hop=STATE_HOP_SENTINEL,
            note=f"shares globals: {sample}{extra}",
        ))
        # Synthesise a state edge per shared identifier between this
        # co-reader and a seed function (we don't record per-seed
        # pairs; just emit one edge per identifier with the seed
        # designator left abstract — the LLM resolves it via the
        # node list).
        for ident in sorted(idents):
            state_edges.append(NeighborhoodEdge(
                src="<seed>", dst=fn, kind="state", ref=ident,
            ))

    return state_nodes, seed_idents, state_edges


def _extract_identifier_from_summary(summary: str) -> str | None:
    """Best-effort extract of an identifier name from a def_use
    row's summary. Older substrate rows write a summary like
    ``"def foo"`` or ``"use bar"``; newer rows include ``ref``
    explicitly. Pure substrate-level parsing — no project-specific
    knowledge."""
    s = summary.strip()
    if not s:
        return None
    # Patterns: "def <ident>", "use <ident>", "<ident> assigned".
    parts = s.split()
    if len(parts) >= 2 and parts[0] in ("def", "use"):
        cand = parts[1].rstrip(",.;:")
        if cand and (cand[0].isalpha() or cand[0] == "_"):
            return cand
    if len(parts) >= 2 and parts[1] in ("assigned", "read", "write", "written"):
        cand = parts[0].rstrip(",.;:")
        if cand and (cand[0].isalpha() or cand[0] == "_"):
            return cand
    return None


def _edge_endpoints_in(
    keep_set: set[tuple[str, str]],
    edge: NeighborhoodEdge,
) -> bool:
    """An edge is kept iff both endpoints are present in the
    neighborhood. State edges with the abstract ``<seed>`` source
    are kept as long as the destination is in. Endpoints are
    matched by function name; the edge's ``file`` field, when
    present, refines but does not strictly disambiguate."""
    if edge.src == "<seed>":
        return any(fn == edge.dst for fn, _f in keep_set)
    src_match = any(fn == edge.src for fn, _f in keep_set)
    dst_match = any(fn == edge.dst for fn, _f in keep_set)
    return src_match and dst_match
