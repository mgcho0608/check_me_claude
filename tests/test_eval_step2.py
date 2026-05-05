"""Tests for the Step 2 entrypoint matcher (deterministic)."""

from __future__ import annotations

from check_me.eval.step2_match import match_entrypoints


def _ep_doc(entries):
    return {
        "schema_version": "v1", "project": "p", "cve": "CVE-X",
        "entrypoints": entries,
    }


def _ep(fn, status="kept", file="x.c"):
    return {"id": "EP-X", "function": fn, "file": file, "status": status,
            "trigger_type": "callback", "confidence": "high"}


def test_perfect_match():
    g = _ep_doc([_ep("a"), _ep("b")])
    o = _ep_doc([_ep("a"), _ep("b")])
    rep = match_entrypoints(g, o)
    assert rep.gold_kept_recall == 1.0
    assert rep.gold_kept_in_our_kept == 2
    assert rep.gold_kept_missing == 0


def test_gold_kept_in_our_quarantined_is_soft_loss():
    g = _ep_doc([_ep("a", status="kept")])
    o = _ep_doc([_ep("a", status="quarantined")])
    rep = match_entrypoints(g, o)
    assert rep.gold_kept_in_our_quarantined == 1
    assert rep.gold_kept_recall == 0.0  # strict-kept recall
    assert rep.gold_kept_anywhere_recall == 1.0  # function preserved
    assert rep.gold_kept_in_our_quarantined_examples


def test_gold_kept_missing_is_silent_fn():
    g = _ep_doc([_ep("a")])
    o = _ep_doc([_ep("b")])
    rep = match_entrypoints(g, o)
    assert rep.gold_kept_missing == 1
    assert rep.gold_kept_anywhere_recall == 0.0


def test_quarantine_tracking():
    g = _ep_doc([_ep("a", "kept"), _ep("b", "quarantined")])
    o = _ep_doc([_ep("a", "kept"), _ep("b", "quarantined")])
    rep = match_entrypoints(g, o)
    assert rep.gold_quarantined_in_our_quarantined == 1
    assert rep.gold_quarantined_total == 1


def test_extras_dont_fail_recall():
    """Our pipeline finds entrypoints gold didn't curate. That
    should NOT lower recall — gold is a curated subset."""
    g = _ep_doc([_ep("a", "kept")])
    o = _ep_doc([_ep("a", "kept"), _ep("extra", "kept")])
    rep = match_entrypoints(g, o)
    assert rep.gold_kept_recall == 1.0
    assert rep.our_kept_no_gold == 1


def test_function_only_match_ignores_file():
    """Same function name in different files still matches. Gold
    typically picks one canonical row per function."""
    g = _ep_doc([_ep("a", file="src/a.c")])
    o = _ep_doc([_ep("a", file="src/different.c")])
    rep = match_entrypoints(g, o)
    assert rep.gold_kept_in_our_kept == 1
