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


def test_call_graph_neighborhood_extracted():
    """Edges where caller OR callee touches a candidate should appear
    in the slice; unrelated edges should not."""
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


def test_evidence_anchors_filtered_by_file():
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


def test_call_edge_cap_applied_after_relevance_filter():
    """The ``max_call_edges`` cap kicks in *after* the relevance
    filter, so it never drops something the miner needs."""
    sub = _empty_substrate()
    sub["categories"]["trust_boundaries"].append({
        "kind": "network_socket", "function": "entry",
        "file": "f.c", "line": 1, "direction": "untrusted_to_trusted",
    })
    # 50 relevant + 1000 irrelevant edges; cap at 30 → 30 relevant kept,
    # all irrelevant dropped (relevance filter wins).
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
    assert all(e["caller"] == "entry" for e in s.call_graph)


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
