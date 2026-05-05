"""Tests for the Step 1 substrate matcher (deterministic)."""

from __future__ import annotations

from check_me.eval.step1_match import match_substrate


def _empty_substrate(project="p", cve="CVE-X"):
    return {
        "schema_version": "v1", "project": project, "cve": cve,
        "categories": {
            "call_graph": [], "data_control_flow": [], "guards": [],
            "trust_boundaries": [], "config_mode_command_triggers": [],
            "callback_registrations": [], "evidence_anchors": [],
        },
    }


def test_empty_substrates_yield_perfect_recall():
    rep = match_substrate(_empty_substrate(), _empty_substrate())
    assert rep.overall_recall == 1.0
    for cat in rep.categories.values():
        assert cat.tp == cat.fn == cat.fp == 0


def test_call_graph_exact_match():
    g = _empty_substrate(); o = _empty_substrate()
    edge = {"caller": "f", "callee": "g", "kind": "direct", "file": "x.c", "line": 1}
    g["categories"]["call_graph"].append(edge)
    o["categories"]["call_graph"].append(edge)
    rep = match_substrate(g, o)
    cg = rep.categories["call_graph"]
    assert cg.tp == 1 and cg.fn == 0 and cg.fp == 0
    assert cg.recall == 1.0


def test_call_graph_missing_edge_counts_as_fn():
    g = _empty_substrate(); o = _empty_substrate()
    g["categories"]["call_graph"].append(
        {"caller": "f", "callee": "g", "kind": "direct"}
    )
    rep = match_substrate(g, o)
    cg = rep.categories["call_graph"]
    assert cg.tp == 0 and cg.fn == 1
    assert cg.recall == 0.0
    assert len(cg.fn_examples) == 1


def test_call_graph_extra_edge_counts_as_fp():
    g = _empty_substrate(); o = _empty_substrate()
    o["categories"]["call_graph"].append(
        {"caller": "extra", "callee": "h", "kind": "direct"}
    )
    rep = match_substrate(g, o)
    cg = rep.categories["call_graph"]
    assert cg.tp == 0 and cg.fp == 1
    # Extras don't affect recall.
    assert cg.recall == 1.0


def test_trust_boundary_match_keys():
    g = _empty_substrate(); o = _empty_substrate()
    row = {
        "kind": "network_socket", "function": "f", "file": "x.c", "line": 1,
        "direction": "untrusted_to_trusted", "note": "via recv",
    }
    g["categories"]["trust_boundaries"].append(row)
    # Match-by-(function, kind, direction): same triple, different note → match.
    o["categories"]["trust_boundaries"].append({
        **row, "note": "different note text", "line": 999,
    })
    rep = match_substrate(g, o)
    tb = rep.categories["trust_boundaries"]
    assert tb.tp == 1 and tb.fn == 0


def test_guard_match_loose_on_first_words():
    """Match-by-(function, first 10 words of guard_call) — wording
    differences in long predicates don't fail the match."""
    g = _empty_substrate(); o = _empty_substrate()
    g["categories"]["guards"].append({
        "function": "f", "file": "x.c", "guard_call": "if (x > 0) return -1;",
        "guard_line": 5, "result_used": True,
    })
    o["categories"]["guards"].append({
        "function": "f", "file": "x.c",
        "guard_call": "if (x > 0) return -1;",  # same first words
        "guard_line": 5, "result_used": True,
    })
    rep = match_substrate(g, o)
    assert rep.categories["guards"].tp == 1


def test_evidence_anchors_match_by_file_line_kind():
    g = _empty_substrate(); o = _empty_substrate()
    g["categories"]["evidence_anchors"].append(
        {"file": "x.c", "line": 42, "kind": "magic_value", "note": "g"}
    )
    o["categories"]["evidence_anchors"].append(
        {"file": "x.c", "line": 42, "kind": "magic_value", "note": "o"}
    )
    rep = match_substrate(g, o)
    assert rep.categories["evidence_anchors"].tp == 1


def test_config_triggers_match():
    g = _empty_substrate(); o = _empty_substrate()
    g["categories"]["config_mode_command_triggers"].append(
        {"kind": "ifdef", "name": "WITH_X", "file": "x.c", "line": 1}
    )
    o["categories"]["config_mode_command_triggers"].append(
        {"kind": "ifdef", "name": "WITH_X", "file": "x.c", "line": 1}
    )
    rep = match_substrate(g, o)
    assert rep.categories["config_mode_command_triggers"].tp == 1


def test_overall_recall_aggregates_across_categories():
    g = _empty_substrate(); o = _empty_substrate()
    # Two gold edges, one matched.
    g["categories"]["call_graph"] = [
        {"caller": "a", "callee": "b", "kind": "direct"},
        {"caller": "a", "callee": "c", "kind": "direct"},
    ]
    o["categories"]["call_graph"] = [
        {"caller": "a", "callee": "b", "kind": "direct"},
    ]
    rep = match_substrate(g, o)
    assert rep.overall_recall == 0.5  # 1/(1+1)
