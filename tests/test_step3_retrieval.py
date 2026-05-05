"""Tests for the deterministic Step 3 retrieval (N=2 hybrid)."""

from __future__ import annotations

from check_me.step3.retrieval import (
    Neighborhood,
    NeighborhoodEdge,
    NeighborhoodNode,
    compute_neighborhood,
)


def _sub(call_graph=None, dcf=None, **kw) -> dict:
    return {
        "schema_version": "v1",
        "project": "p", "cve": "CVE-T",
        "categories": {
            "call_graph": call_graph or [],
            "data_control_flow": dcf or [],
            "guards": [], "trust_boundaries": [],
            "config_mode_command_triggers": [],
            "callback_registrations": [], "evidence_anchors": [],
        },
    }


def test_seed_only_when_no_edges():
    n = compute_neighborhood(_sub(), entry_function="foo", entry_file="f.c")
    assert n.entry.function == "foo"
    assert n.entry.role == "entry"
    # Only the seed itself, no other nodes.
    assert [x.function for x in n.nodes] == ["foo"]


def test_one_hop_callee_in_neighborhood():
    sub = _sub(call_graph=[
        {"caller": "foo", "callee": "bar", "file": "f.c", "line": 5, "kind": "direct"},
    ])
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c")
    funcs = {x.function for x in n.nodes}
    assert "foo" in funcs
    assert "bar" in funcs
    assert any(e.src == "foo" and e.dst == "bar" and e.kind == "call_direct"
               for e in n.edges), n.edges


def test_one_hop_caller_in_neighborhood():
    sub = _sub(call_graph=[
        {"caller": "outer", "callee": "foo", "file": "g.c", "line": 7, "kind": "direct"},
    ])
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c")
    funcs = {x.function for x in n.nodes}
    assert "outer" in funcs
    assert any(e.src == "outer" and e.dst == "foo" for e in n.edges)


def test_two_hop_callee_reaches_distance_2():
    sub = _sub(call_graph=[
        {"caller": "foo", "callee": "bar", "file": "f.c", "line": 5, "kind": "direct"},
        {"caller": "bar", "callee": "baz", "file": "f.c", "line": 9, "kind": "direct"},
    ])
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c", hop_depth=2)
    funcs = {x.function for x in n.nodes}
    assert "baz" in funcs


def test_three_hop_excluded_with_default_n2():
    sub = _sub(call_graph=[
        {"caller": "foo", "callee": "bar", "file": "f.c", "line": 5, "kind": "direct"},
        {"caller": "bar", "callee": "baz", "file": "f.c", "line": 9, "kind": "direct"},
        {"caller": "baz", "callee": "deep", "file": "f.c", "line": 12, "kind": "direct"},
    ])
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c", hop_depth=2)
    funcs = {x.function for x in n.nodes}
    assert "deep" not in funcs


def test_seed_step_file_anchored_for_outgoing():
    """Two same-named ``foo`` overloads in different TUs. The seed
    is ``foo@a.c``; the seed-step outgoing edge to ``a_helper``
    must be kept and the b.c overload's outgoing edge to
    ``b_helper`` must be excluded."""
    sub = _sub(call_graph=[
        {"caller": "foo", "callee": "a_helper", "file": "a.c", "line": 5, "kind": "direct"},
        {"caller": "foo", "callee": "b_helper", "file": "b.c", "line": 5, "kind": "direct"},
    ])
    n = compute_neighborhood(sub, entry_function="foo", entry_file="a.c")
    funcs = {x.function for x in n.nodes}
    assert "a_helper" in funcs
    assert "b_helper" not in funcs


def test_state_axis_pulls_in_co_reader_of_seed_global():
    """``foo`` reads ``buf``; ``deep`` also reads ``buf`` but is
    not call-graph-reachable from ``foo``. The state axis must
    pull ``deep`` into the neighborhood."""
    sub = _sub(
        call_graph=[],
        dcf=[
            {"function": "foo", "file": "f.c", "kind": "def_use", "ref": "buf",
             "summary": "use buf"},
            {"function": "deep", "file": "g.c", "kind": "def_use", "ref": "buf",
             "summary": "use buf"},
        ],
    )
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c")
    funcs = {x.function for x in n.nodes}
    assert "deep" in funcs
    assert "buf" in n.shared_globals
    # The state edge is synthesised from <seed> to the co-reader.
    assert any(e.kind == "state" and e.dst == "deep" and e.ref == "buf"
               for e in n.edges), n.edges


def test_state_axis_uses_hop_1_call_neighbours_not_just_seed():
    """The seed's hop-1 call neighbours also contribute their
    referenced identifiers to the state axis. Models the
    ``process_thread_tcpip_process → tcpip_input → uip_input →
    uip_process`` pattern: ``uip_process`` shares ``uip_buf`` with
    ``tcpip_input`` (a hop-1 callee of the seed), even though no
    call edge between seed and ``uip_process`` exists within 2
    hops."""
    sub = _sub(
        call_graph=[
            {"caller": "seed", "callee": "near", "file": "f.c", "line": 5, "kind": "direct"},
        ],
        dcf=[
            {"function": "near", "file": "f.c", "kind": "def_use", "ref": "shared",
             "summary": "use shared"},
            {"function": "far", "file": "g.c", "kind": "def_use", "ref": "shared",
             "summary": "use shared"},
        ],
    )
    n = compute_neighborhood(sub, entry_function="seed", entry_file="f.c")
    funcs = {x.function for x in n.nodes}
    assert "far" in funcs


def test_node_role_tags_distinguish_call_vs_state_neighbours():
    sub = _sub(
        call_graph=[
            {"caller": "seed", "callee": "near", "file": "f.c", "line": 5, "kind": "direct"},
        ],
        dcf=[
            {"function": "seed", "file": "f.c", "kind": "def_use", "ref": "buf",
             "summary": "use buf"},
            {"function": "far", "file": "g.c", "kind": "def_use", "ref": "buf",
             "summary": "use buf"},
        ],
    )
    n = compute_neighborhood(sub, entry_function="seed", entry_file="f.c")
    by_role = {x.function: x.role for x in n.nodes}
    assert by_role["seed"] == "entry"
    assert by_role["near"] == "call_neighbour"
    assert by_role["far"] == "state_neighbour"


def test_neighborhood_capping_protects_call_axis_first():
    """When max_nodes is hit, the call-axis chain (which is
    structurally relevant) is preserved; the state-axis tail is
    trimmed first."""
    sub = _sub(
        call_graph=[
            {"caller": "seed", "callee": f"call_{i}", "file": "f.c", "line": i, "kind": "direct"}
            for i in range(5)
        ],
        dcf=(
            [{"function": "seed", "file": "f.c", "kind": "def_use", "ref": "buf",
              "summary": "use buf"}]
            + [{"function": f"state_{i}", "file": f"s{i}.c", "kind": "def_use",
                "ref": "buf", "summary": "use buf"} for i in range(20)]
        ),
    )
    n = compute_neighborhood(sub, entry_function="seed", entry_file="f.c", max_nodes=10)
    funcs = [x.function for x in n.nodes]
    # All 5 call-axis neighbours preserved.
    for i in range(5):
        assert f"call_{i}" in funcs, funcs
    # Some state neighbours dropped.
    assert n.truncated
    state_kept = [f for f in funcs if f.startswith("state_")]
    assert 0 < len(state_kept) <= 4  # 10 cap - 1 entry - 5 call = 4 state slots


def test_dcf_summary_fallback_extracts_identifier():
    """Older substrate rows have no ``ref`` field; the identifier
    must be parsed from the ``summary`` text."""
    sub = _sub(
        call_graph=[],
        dcf=[
            {"function": "foo", "file": "f.c", "kind": "def_use", "summary": "use buf"},
            {"function": "deep", "file": "g.c", "kind": "def_use", "summary": "use buf"},
        ],
    )
    n = compute_neighborhood(sub, entry_function="foo", entry_file="f.c")
    funcs = {x.function for x in n.nodes}
    assert "deep" in funcs


def test_edges_filtered_to_neighborhood_endpoints():
    """An edge whose endpoint was capped out of the node set is
    dropped — keeping it would leave a dangling reference."""
    sub = _sub(
        call_graph=[
            {"caller": "seed", "callee": "near", "file": "f.c", "line": 5, "kind": "direct"},
            {"caller": "near", "callee": "far", "file": "f.c", "line": 9, "kind": "direct"},
            {"caller": "far",  "callee": "deep", "file": "f.c", "line": 12, "kind": "direct"},
        ],
    )
    n = compute_neighborhood(sub, entry_function="seed", entry_file="f.c", max_nodes=2)
    # Only the seed itself + 1 more node fit the cap.
    assert len(n.nodes) <= 2
    # Edges with endpoints outside the kept set must be dropped.
    for e in n.edges:
        if e.src != "<seed>":
            srcs = {x.function for x in n.nodes}
            dsts = {x.function for x in n.nodes}
            assert e.src in srcs and e.dst in dsts, (e, srcs, dsts)


def test_no_dataset_specific_branching():
    """Same logical input + different project name → same retrieval."""
    a = _sub(
        call_graph=[{"caller": "f", "callee": "g", "file": "x.c", "line": 1, "kind": "direct"}],
    )
    b = _sub(
        call_graph=[{"caller": "f", "callee": "g", "file": "x.c", "line": 1, "kind": "direct"}],
    )
    a["project"] = "contiki-ng"; b["project"] = "libssh"
    na = compute_neighborhood(a, entry_function="f", entry_file="x.c")
    nb = compute_neighborhood(b, entry_function="f", entry_file="x.c")
    # The retrieval depends on substrate, not on project name.
    assert [x.function for x in na.nodes] == [x.function for x in nb.nodes]
