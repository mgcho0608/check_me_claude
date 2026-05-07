"""Pytest for step2.substrate_slice — project-agnostic substrate distillation."""

from __future__ import annotations

from check_me.step2.substrate_slice import slice_substrate, SubstrateSlice


def _empty_substrate(project="t", cve="CVE-X"):
    return {
        "schema_version": "v1",
        "project": project,
        "cve": cve,
        "categories": {
            "call_graph": [],
            "data_control_flow": [],
            "guards": [],
            "trust_boundaries": [],
            "config_mode_command_triggers": [],
            "callback_registrations": [],
            "evidence_anchors": [],
        },
    }


def test_empty_substrate_yields_empty_slice():
    s = slice_substrate(_empty_substrate())
    assert s.row_counts() == {
        "trust_boundaries": 0,
        "callback_registrations": 0,
        "config_mode_command_triggers": 0,
        "call_graph": 0,
        "guards": 0,
        "evidence_anchors": 0,
        "candidate_functions": 0,
    }


def test_trust_boundary_function_added_to_candidates():
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "handle_packet",
        "file": "net.c", "line": 42, "direction": "untrusted_to_trusted",
    })
    s = slice_substrate(sub)
    assert "handle_packet" in s.candidate_functions
    assert len(s.trust_boundaries) == 1


def test_callback_function_added_to_candidates():
    sub = _empty_substrate()
    sub["categories"]["callback_registrations"].append({
        "registration_site": "table[]",
        "callback_function": "my_handler",
        "file": "h.c", "line": 10, "kind": "function_table",
    })
    s = slice_substrate(sub)
    assert "my_handler" in s.candidate_functions
    assert len(s.callback_registrations) == 1


def test_cross_tu_callee_NOT_added_unless_anchored():
    """An anchor-based pool admits a callee only via 1-hop closure
    over (trust_boundaries ∪ callback_registrations). A cross-TU
    callee whose caller is itself unanchored is NOT added to the
    pool — earlier revisions added every cross-TU callee as a
    speculative cut, but that mixed high-precision attacker-input
    markers with structural over-collection (most cross-TU callees
    are internal helpers, not entrypoints). PLAN §6 Rule 2 is
    satisfied by the verifier's per-candidate hop=2 + source-
    aware critique, not by widening the pool here."""
    sub = _empty_substrate()
    # Caller in api.c (no trust/callback row) calls helper(). Both
    # are project-internal symbols with no anchor, so neither
    # enters the pool.
    sub["categories"]["call_graph"] = [
        {"caller": "api_call", "callee": "helper",
         "file": "api.c", "line": 10, "kind": "direct"},
    ]
    sub["categories"]["guards"] = [
        {"function": "helper", "file": "lib.c", "guard_call": "n>0",
         "guard_line": 5, "result_used": True},
    ]
    s = slice_substrate(sub)
    assert "helper" not in s.candidate_functions
    assert "api_call" not in s.candidate_functions


def test_intra_tu_callee_NOT_added_to_candidates():
    """A function called only from within its own definition file
    is a local helper, not an entrypoint. Neither caller nor
    callee enter the pool unless they're anchored (trust /
    callback) or 1-hop downstream of an anchor."""
    sub = _empty_substrate()
    sub["categories"]["call_graph"] = [
        {"caller": "outer", "callee": "local_helper",
         "file": "f.c", "line": 10, "kind": "direct"},
    ]
    sub["categories"]["guards"] = [
        {"function": "local_helper", "file": "f.c", "guard_call": "x",
         "guard_line": 5, "result_used": True},
    ]
    s = slice_substrate(sub)
    # No anchor -> no candidate.
    assert "local_helper" not in s.candidate_functions
    assert "outer" not in s.candidate_functions


def test_callback_handler_callee_added_to_candidates():
    """When an external trigger fires a callback and the callback
    wraps an internal dispatch function, the dispatch function is
    itself an entry point — attacker-controlled bytes flow from
    the callback into it. libssh's
    ``ssh_packet_socket_callback -> ssh_packet_process`` is the
    canonical case; same layered-protocol shape appears in any C
    codebase. Generic 1-hop closure over registered callbacks."""
    sub = _empty_substrate()
    # Callback registered via function-table.
    sub["categories"]["callback_registrations"].append({
        "registration_site": "table[]",
        "callback_function": "recv_callback",
        "file": "net.c", "line": 5, "kind": "function_table",
    })
    # Callback dispatches to a same-TU helper.
    sub["categories"]["call_graph"] = [
        {"caller": "recv_callback", "callee": "process_request",
         "file": "net.c", "line": 12, "kind": "direct"},
    ]
    s = slice_substrate(sub)
    assert "recv_callback" in s.candidate_functions
    # The 1-hop dispatch target is itself an entrypoint.
    assert "process_request" in s.candidate_functions


def test_slice_for_candidate_chunk_call_graph_scoped_to_chunk_set_only():
    """The chunk slice's call_graph contains edges where chunk_set
    is endpoint (caller or callee) — *not* the induced subgraph of
    the hop=N neighbourhood. Internal edges between neighbour
    functions belong to the verifier's per-candidate slice (hop=2
    + source); the chunk miner only needs to see how each
    chunk_set candidate is invoked and what it dispatches into."""
    from check_me.step2.substrate_slice import (
        slice_for_candidate_chunk,
        slice_substrate,
    )
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = [
        # entry's edges (chunk_set endpoint) — KEPT.
        {"caller": "entry", "callee": "helper",
         "file": "f.c", "line": 5, "kind": "direct"},
        {"caller": "outer", "callee": "entry",
         "file": "g.c", "line": 3, "kind": "direct"},
        # Internal edge between two neighbours — DROPPED in the
        # chunk slice (verifier sees it via hop=2).
        {"caller": "helper", "callee": "deeper",
         "file": "f.c", "line": 8, "kind": "direct"},
    ]
    full = slice_substrate(sub)
    chunk_slice = slice_for_candidate_chunk(
        full, chunk_candidates=["entry"], hop_depth=1,
    )
    pairs = sorted(
        (e["caller"], e["callee"]) for e in chunk_slice.call_graph
    )
    assert ("entry", "helper") in pairs
    assert ("outer", "entry") in pairs
    assert ("helper", "deeper") not in pairs


def test_call_graph_root_NOT_added_unless_anchored():
    """The earlier "every caller-but-never-callee is a candidate"
    cut was an over-collection workaround for sparse Step 1
    coverage. The anchor-based pool drops it: a root is admitted
    only if it is itself an anchor (trust / callback) or a 1-hop
    callee of one. Reasoning: many "roots" in extracted call
    graphs are orphans whose callers were not extracted, not real
    program entry points; treating every root as a candidate
    pushed structural noise onto the LLM verifier."""
    sub = _empty_substrate()
    sub["categories"]["call_graph"] = [
        {"caller": "main", "callee": "do_work",
         "file": "main.c", "line": 5, "kind": "direct"},
        {"caller": "do_work", "callee": "lib_func",
         "file": "main.c", "line": 12, "kind": "direct"},
    ]
    s = slice_substrate(sub)
    # No anchor row exists -> nothing in the pool, including main.
    assert s.candidate_functions == []


def test_trust_boundary_callee_added_to_candidates():
    """1-hop callee of a trust_boundary IS in the pool. When a
    boundary handler delegates one hop further into an internal
    dispatch function, that delegate is itself attacker-reachable
    (bytes flow from the boundary into it)."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "recv_socket",
        "file": "net.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = [
        {"caller": "recv_socket", "callee": "handle_message",
         "file": "net.c", "line": 12, "kind": "direct"},
        # Indirect 2-hop callee — must NOT enter (anchor closure
        # is 1-hop, deeper validation is the verifier's job).
        {"caller": "handle_message", "callee": "deep_helper",
         "file": "net.c", "line": 30, "kind": "direct"},
    ]
    s = slice_substrate(sub)
    assert "recv_socket" in s.candidate_functions
    assert "handle_message" in s.candidate_functions
    assert "deep_helper" not in s.candidate_functions


def test_call_graph_neighborhood_filtered_by_anchor_closure():
    """Edges where neither endpoint is in the candidate pool are
    dropped — only edges touching the anchor or its 1-hop closure
    survive. ``(x, y)`` here has no anchor connection so its row
    is filtered. ``(entry, helper)`` and ``(z, entry)`` both touch
    the anchor (``entry`` is a trust_boundary; ``helper`` is a
    1-hop callee of an anchor — they're both pool members; ``z``
    is not, but the edge still survives because ``entry`` is)."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = [
        {"caller": "entry", "callee": "helper", "file": "f.c", "line": 5, "kind": "direct"},
        {"caller": "x", "callee": "y", "file": "g.c", "line": 1, "kind": "direct"},
        {"caller": "z", "callee": "entry", "file": "h.c", "line": 7, "kind": "direct"},
    ]
    s = slice_substrate(sub)
    cg_pairs = sorted((e["caller"], e["callee"]) for e in s.call_graph)
    assert cg_pairs == [("entry", "helper"), ("z", "entry")]


def test_guards_filtered_to_neighborhood():
    """Guards are kept for functions in the candidate-expanded
    set: candidates plus the neighbors reached via call_graph
    edges that touch a candidate. ``unrelated`` is not in the
    pool (guards is not a pool source — see candidate-pool
    docstring) and not in any neighborhood edge of a candidate,
    so its guard row is dropped."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = [
        {"caller": "entry", "callee": "helper", "file": "f.c", "line": 5, "kind": "direct"},
    ]
    sub["categories"]["guards"] = [
        {"function": "entry", "file": "f.c", "guard_call": "x>0",
         "guard_line": 2, "result_used": True},
        {"function": "helper", "file": "f.c", "guard_call": "y<0",
         "guard_line": 7, "result_used": True},
        {"function": "unrelated", "file": "z.c", "guard_call": "q",
         "guard_line": 1, "result_used": True},
    ]
    s = slice_substrate(sub)
    funcs = sorted(g["function"] for g in s.guards)
    assert funcs == ["entry", "helper"]
    assert "unrelated" not in funcs


def test_evidence_anchors_kept_when_file_carries_candidate_relevant_row():
    """An anchor row in a file that hosts a candidate-relevant row
    (trust boundary, callback registration, neighborhood call edge,
    or relevant guard) is kept. ``other.c`` here has no such row,
    so its anchor is dropped — file-based filter survives the
    pool expansion because ``relevant_files`` is derived from rows
    actually emitted in the slice, not from the candidate pool
    membership directly."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["evidence_anchors"] = [
        {"file": "f.c", "line": 10, "kind": "magic_value"},
        {"file": "other.c", "line": 1, "kind": "magic_value"},
    ]
    s = slice_substrate(sub)
    files = {a["file"] for a in s.evidence_anchors}
    assert files == {"f.c"}


def test_config_triggers_filtered_to_candidate_relevant_files():
    """``config_mode_command_triggers`` is filtered to files that
    contain candidate-relevant rows. A project-wide enumeration would
    swamp the slice on large CMake projects (libssh's full project
    enum is ~645 rows; only ~250 land in candidate files). Triggers
    in unrelated files are dropped."""
    sub = _empty_substrate()
    # One candidate function whose row pins file=f.c.
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["config_mode_command_triggers"] = [
        # In the candidate file — kept.
        {"kind": "ifdef", "name": "WITH_X", "file": "f.c", "line": 5},
        # In an unrelated file — dropped.
        {"kind": "compile_flag", "name": "BUILD_MODE",
         "file": "unrelated.c", "line": 0},
    ]
    s = slice_substrate(sub)
    assert len(s.config_mode_command_triggers) == 1
    assert s.config_mode_command_triggers[0]["file"] == "f.c"


def test_call_edge_cap_bounds_slice_size():
    """The ``max_call_edges`` cap bounds the slice. ``entry`` is the
    anchor and its 1-hop callees ``helper_0..helper_49`` enter the
    pool (50 candidates). Edges where neither endpoint is in the
    pool (``x_i -> y_i``) are filtered first; among the 50
    anchor-relevant edges the cap selects the first 30 via the
    round-robin per-candidate selector."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = (
        [
            {"caller": "entry", "callee": f"helper_{i}",
             "file": "f.c", "line": i + 10, "kind": "direct"}
            for i in range(50)
        ]
        + [
            {"caller": f"x{i}", "callee": f"y{i}",
             "file": "g.c", "line": i + 1, "kind": "direct"}
            for i in range(1000)
        ]
    )
    s = slice_substrate(sub, max_call_edges=30)
    assert len(s.call_graph) == 30


def test_to_json_dict_matches_dataclass_fields():
    """Serialised slice must contain exactly the documented keys."""
    s = slice_substrate(_empty_substrate())
    d = s.to_json_dict()
    assert set(d.keys()) == {
        "project", "cve", "candidate_functions",
        "trust_boundaries", "callback_registrations",
        "config_mode_command_triggers", "call_graph",
        "guards", "evidence_anchors",
    }


def test_slice_is_deterministic():
    """Same input → same JSON. The slice contract."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"] = [
        {"kind": "network_socket", "function": "b",
         "file": "b.c", "line": 1, "direction": "untrusted_to_trusted"},
        {"kind": "network_socket", "function": "a",
         "file": "a.c", "line": 1, "direction": "untrusted_to_trusted"},
    ]
    a = slice_substrate(sub).to_json()
    b = slice_substrate(sub).to_json()
    assert a == b


def test_load_from_json_string_and_path(tmp_path):
    p = tmp_path / "sub.json"
    sub = _empty_substrate("p1", "CVE-1")
    p.write_text(__import__("json").dumps(sub))
    s_str = slice_substrate(p.read_text())
    s_path = slice_substrate(p)
    s_dict = slice_substrate(sub)
    assert s_str.project == s_path.project == s_dict.project == "p1"


def _full_slice_for_focusing_tests():
    """A non-trivial full slice with two candidate functions in
    different files — used to verify the per-candidate focus
    correctly narrows the substrate."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"] = [
        {"kind": "network_socket", "function": "alpha",
         "file": "a.c", "line": 1, "direction": "untrusted_to_trusted"},
        {"kind": "network_socket", "function": "beta",
         "file": "b.c", "line": 2, "direction": "untrusted_to_trusted"},
        {"kind": "file_read", "function": "alpha_helper",
         "file": "a.c", "line": 50, "direction": "untrusted_to_trusted"},
    ]
    sub["categories"]["callback_registrations"] = [
        {"registration_site": "T[]", "callback_function": "alpha",
         "file": "a.c", "line": 5, "kind": "function_table"},
        {"registration_site": "U[]", "callback_function": "beta",
         "file": "b.c", "line": 10, "kind": "function_table"},
    ]
    sub["categories"]["call_graph"] = [
        {"caller": "alpha", "callee": "alpha_helper", "file": "a.c", "line": 7, "kind": "direct"},
        {"caller": "beta", "callee": "other", "file": "b.c", "line": 3, "kind": "direct"},
        {"caller": "z", "callee": "alpha", "file": "z.c", "line": 1, "kind": "direct"},
    ]
    sub["categories"]["guards"] = [
        {"function": "alpha", "file": "a.c", "guard_call": "x>0",
         "guard_line": 4, "result_used": True},
        {"function": "beta", "file": "b.c", "guard_call": "y!=0",
         "guard_line": 6, "result_used": True},
    ]
    sub["categories"]["evidence_anchors"] = [
        {"file": "a.c", "line": 100, "kind": "magic_value"},
        {"file": "b.c", "line": 200, "kind": "magic_value"},
    ]
    sub["categories"]["config_mode_command_triggers"] = [
        {"kind": "ifdef", "name": "WITH_A", "file": "a.c", "line": 1},
        {"kind": "ifdef", "name": "WITH_B", "file": "b.c", "line": 1},
    ]
    return slice_substrate(sub)


def test_slice_for_candidate_narrows_to_function_only_guards():
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    # Only guards in alpha — beta's guards must drop.
    assert {g["function"] for g in focused.guards} == {"alpha"}


def test_slice_for_candidate_call_graph_is_neighborhood_induced_subgraph():
    """The call_graph in the focused slice is the induced subgraph
    of the candidate's ``hop_depth``-neighbourhood (default 2 —
    matches Step 3's N=2 retrieval, gives the verifier visibility
    into wrapper-style chains where the candidate dispatches to
    helpers that touch syscalls). Edges into / out of an
    unrelated candidate's subgraph (here ``beta -> other``) must
    not appear in alpha's focused slice."""
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    pairs = sorted({(e["caller"], e["callee"]) for e in focused.call_graph})
    # Alpha's 2-hop neighbourhood: {alpha, alpha_helper, z}. The
    # induced subgraph contains alpha->alpha_helper and z->alpha.
    assert ("alpha", "alpha_helper") in pairs
    assert ("z", "alpha") in pairs
    # Beta's subgraph is disjoint from alpha's: must not leak.
    assert ("beta", "other") not in pairs


def test_slice_for_candidate_two_hop_reaches_callees_of_callees():
    """When the candidate's 1-hop callee itself calls a syscall
    wrapper, the verifier sees that 2-hop edge — this is what
    enables wrapper-style entrypoint validation. ``hop_depth=1``
    would have hidden the chain end."""
    from check_me.step2.substrate_slice import (
        slice_for_candidate,
        slice_substrate,
    )
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"] = [
        # Candidate (entry function) — not itself a syscall.
        {"kind": "network_socket", "function": "entry",
         "file": "a.c", "line": 1, "direction": "untrusted_to_trusted"},
        # 2-hop downstream — the actual syscall site.
        {"kind": "network_socket", "function": "deep_io",
         "file": "c.c", "line": 30, "direction": "untrusted_to_trusted"},
    ]
    sub["categories"]["call_graph"] = [
        {"caller": "entry", "callee": "wrapper",
         "file": "a.c", "line": 5, "kind": "direct"},
        {"caller": "wrapper", "callee": "deep_io",
         "file": "b.c", "line": 20, "kind": "direct"},
    ]
    full = slice_substrate(sub)
    focused = slice_for_candidate(full,
                                  candidate_function="entry",
                                  candidate_file="a.c",
                                  hop_depth=2)
    funcs_in_edges = {e["caller"] for e in focused.call_graph} | {
        e["callee"] for e in focused.call_graph
    }
    assert "deep_io" in funcs_in_edges, (
        "2-hop neighbourhood should reach the syscall site through wrapper"
    )
    # And the trust_boundary at the chain end should be in the slice
    # so the verifier can cite it as evidence of attacker-controlled
    # bytes flowing through the candidate.
    deep_io_tb = [r for r in focused.trust_boundaries if r.get("function") == "deep_io"]
    assert len(deep_io_tb) == 1, focused.trust_boundaries


def test_slice_for_candidate_hop_depth_one_falls_back_to_direct_neighbours():
    """``hop_depth=1`` keeps only the candidate's direct callees /
    callers — useful as a tightening knob on very dense graphs."""
    from check_me.step2.substrate_slice import (
        slice_for_candidate,
        slice_substrate,
    )
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"] = [
        {"kind": "network_socket", "function": "entry",
         "file": "a.c", "line": 1, "direction": "untrusted_to_trusted"},
        {"kind": "network_socket", "function": "deep_io",
         "file": "c.c", "line": 30, "direction": "untrusted_to_trusted"},
    ]
    sub["categories"]["call_graph"] = [
        {"caller": "entry", "callee": "wrapper",
         "file": "a.c", "line": 5, "kind": "direct"},
        {"caller": "wrapper", "callee": "deep_io",
         "file": "b.c", "line": 20, "kind": "direct"},
    ]
    full = slice_substrate(sub)
    focused = slice_for_candidate(full,
                                  candidate_function="entry",
                                  candidate_file="a.c",
                                  hop_depth=1)
    funcs_in_edges = {e["caller"] for e in focused.call_graph} | {
        e["callee"] for e in focused.call_graph
    }
    assert "deep_io" not in funcs_in_edges
    deep_io_tb = [r for r in focused.trust_boundaries if r.get("function") == "deep_io"]
    assert deep_io_tb == []


def test_slice_for_candidate_callback_registrations_match_function():
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    cb_funcs = {r["callback_function"] for r in focused.callback_registrations}
    assert "alpha" in cb_funcs
    # beta's callback should drop because beta is in b.c, not a.c.
    assert "beta" not in cb_funcs


def test_slice_for_candidate_anchors_filtered_by_file():
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    files = {a["file"] for a in focused.evidence_anchors}
    assert files == {"a.c"}


def test_slice_for_candidate_config_triggers_filtered_by_file():
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    names = {t["name"] for t in focused.config_mode_command_triggers}
    assert names == {"WITH_A"}


def test_slice_for_candidate_infers_file_when_not_provided():
    """If candidate_file is omitted, slice_for_candidate looks it up
    from the full slice."""
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha")
    # Should still narrow the per-file content to a.c.
    assert all(a["file"] == "a.c" for a in focused.evidence_anchors)


def test_slice_for_candidate_significantly_smaller_than_full():
    """The whole point. Token-cost win."""
    from check_me.step2.substrate_slice import slice_for_candidate
    full = _full_slice_for_focusing_tests()
    focused = slice_for_candidate(full, candidate_function="alpha", candidate_file="a.c")
    full_size = len(full.to_json())
    focused_size = len(focused.to_json())
    assert focused_size < full_size


def test_slice_for_candidate_disambiguates_same_name_overloads():
    """A C codebase often has two ``static`` functions sharing a
    name across translation units (a high-level API stub in one
    file and a low-level handler in another). When ``candidate_file``
    is supplied, ``slice_for_candidate`` must keep evidence about
    *only* that file's overload — leaking the other overload's
    rows would defeat the verifier's job."""
    from check_me.step2.substrate_slice import slice_for_candidate

    sub = _empty_substrate()
    # Two functions named "foo" in different files (the libssh-style
    # case but expressed generically — no project-specific names).
    sub["categories"]["trust_boundaries"] = [
        # Overload A — in api.c. Has a network-socket trust boundary.
        {"kind": "network_socket", "function": "foo",
         "file": "api.c", "line": 100, "direction": "untrusted_to_trusted"},
        # Overload B — in handler.c. Has a file_read trust boundary
        # (irrelevant to overload A).
        {"kind": "file_read", "function": "foo",
         "file": "handler.c", "line": 200, "direction": "untrusted_to_trusted"},
    ]
    sub["categories"]["callback_registrations"] = [
        # Only overload A is registered as a callback.
        {"registration_site": "table[]", "callback_function": "foo",
         "file": "api.c", "line": 50, "kind": "function_table"},
    ]
    sub["categories"]["call_graph"] = [
        # Caller=foo edge in api.c (overload A's body).
        {"caller": "foo", "callee": "helper_a",
         "file": "api.c", "line": 110, "kind": "direct"},
        # Caller=foo edge in handler.c (overload B's body) —
        # MUST NOT appear in overload A's slice.
        {"caller": "foo", "callee": "helper_b",
         "file": "handler.c", "line": 210, "kind": "direct"},
    ]
    sub["categories"]["guards"] = [
        {"function": "foo", "file": "api.c", "guard_call": "x>0",
         "guard_line": 105, "result_used": True},
        # Overload B's guard — must not leak into A's slice.
        {"function": "foo", "file": "handler.c", "guard_call": "y!=0",
         "guard_line": 205, "result_used": True},
    ]
    full = slice_substrate(sub)

    focused = slice_for_candidate(full,
                                  candidate_function="foo",
                                  candidate_file="api.c")

    # trust_boundaries: only the api.c overload's row.
    tb_files = sorted({r["file"] for r in focused.trust_boundaries
                       if r.get("function") == "foo"})
    assert tb_files == ["api.c"], tb_files

    # call_graph: only edges where caller=foo lives in api.c.
    foo_caller_files = sorted({e["file"] for e in focused.call_graph
                               if e.get("caller") == "foo"})
    assert foo_caller_files == ["api.c"], foo_caller_files

    # guards: only the api.c-side guard.
    guard_files = sorted({g["file"] for g in focused.guards})
    assert guard_files == ["api.c"], guard_files


def test_slice_for_candidate_chunk_scopes_candidate_functions_to_chunk():
    """The chunk slice's ``candidate_functions`` lists only the
    chunk's assigned subset, not the full pool. Serialising the
    full pool inflates per-chunk prompt tokens without helping
    Part B (whose vocabulary is callback_registrations / indirect
    edges / trust_boundaries — not a list of names)."""
    from check_me.step2.substrate_slice import (
        slice_for_candidate_chunk,
        slice_substrate,
    )
    sub = _empty_substrate()
    # Three trust-boundary functions become candidates; chunk
    # processes only one of them.
    for fn in ("a", "b", "c"):
        sub["categories"]["trust_boundaries"].append({
            "kind": "network_socket", "function": fn,
            "file": f"{fn}.c", "line": 1,
            "direction": "untrusted_to_trusted",
        })
    full = slice_substrate(sub)
    assert set(full.candidate_functions) >= {"a", "b", "c"}
    chunk_slice = slice_for_candidate_chunk(
        full, chunk_candidates=["b"], hop_depth=2,
    )
    assert chunk_slice.candidate_functions == ["b"]


def test_slice_for_candidate_chunk_scopes_config_triggers_to_chunk_files():
    """``config_mode_command_triggers`` in the chunk slice is
    file-scoped to the chunk neighbourhood (same posture as
    evidence_anchors). Cross-chunk gates outside the chunk's files
    are dropped — the chunk's Part A reasoning does not need them.
    Real-project mode/CLI gates can run 1500-2000 rows; the FULL-
    keep behaviour was the single largest token-budget consumer
    in the chunk slice."""
    from check_me.step2.substrate_slice import (
        slice_for_candidate_chunk,
        slice_substrate,
    )
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    sub["categories"]["call_graph"] = [
        {"caller": "entry", "callee": "helper",
         "file": "f.c", "line": 5, "kind": "direct"},
    ]
    sub["categories"]["config_mode_command_triggers"] = [
        # In chunk-relevant file — kept.
        {"kind": "ifdef", "name": "WITH_X", "file": "f.c", "line": 5},
        # In an unrelated file — dropped.
        {"kind": "ifdef", "name": "WITH_Z", "file": "z.c", "line": 1},
    ]
    full = slice_substrate(sub)
    chunk_slice = slice_for_candidate_chunk(
        full, chunk_candidates=["entry"], hop_depth=2,
    )
    cfg_names = {c["name"] for c in chunk_slice.config_mode_command_triggers}
    assert cfg_names == {"WITH_X"}


def test_no_dataset_specific_branching():
    """The slicer must not behave differently for any specific
    project name. Same logical input + different project name →
    same shape."""
    a = _empty_substrate("contiki-ng", "CVE-X")
    a["categories"]["trust_boundaries"].append(
        {"kind": "network_socket", "function": "f",
         "file": "x.c", "line": 1, "direction": "untrusted_to_trusted"}
    )
    b = _empty_substrate("libssh", "CVE-Y")
    b["categories"]["trust_boundaries"].append(
        {"kind": "network_socket", "function": "f",
         "file": "x.c", "line": 1, "direction": "untrusted_to_trusted"}
    )
    sa = slice_substrate(a)
    sb = slice_substrate(b)
    # Project + cve fields differ. All other selection results are identical.
    sa_d = sa.to_json_dict(); sa_d.pop("project"); sa_d.pop("cve")
    sb_d = sb.to_json_dict(); sb_d.pop("project"); sb_d.pop("cve")
    assert sa_d == sb_d
