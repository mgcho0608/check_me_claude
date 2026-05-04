"""Pytest for step2.prompts — anchoring prevention is the key invariant."""

from __future__ import annotations

import json

from check_me.step2.prompts import (
    MINER_OUTPUT_SCHEMA,
    VERIFIER_OUTPUT_SCHEMA,
    build_miner_messages,
    build_verifier_messages,
    candidate_for_verifier,
)
from check_me.step2.substrate_slice import SubstrateSlice


def _slice():
    return SubstrateSlice(
        project="p", cve="CVE-T",
        candidate_functions=["f"],
        trust_boundaries=[{
            "kind": "network_socket", "function": "f",
            "file": "x.c", "line": 1, "direction": "untrusted_to_trusted",
        }],
    )


# --------- miner ------------


def test_miner_user_message_includes_substrate_slice_json():
    sys, user = build_miner_messages(_slice())
    assert '"trust_boundaries"' in user
    assert '"function": "f"' in user
    assert '"x.c"' in user


def test_miner_system_forbids_dataset_specific_knowledge():
    sys, _ = build_miner_messages(_slice())
    assert "dataset-specific" in sys.lower() or "do not use dataset" in sys.lower()


def test_miner_system_forbids_inventing_lines():
    sys, _ = build_miner_messages(_slice())
    assert "do not invent" in sys.lower() or "do not make up" in sys.lower()


def test_miner_user_message_specifies_output_shape():
    _, user = build_miner_messages(_slice())
    assert '"candidates"' in user
    assert '"trigger_type"' in user
    assert '"supporting_substrate_edges"' in user


def test_miner_schema_enumerates_trigger_types():
    enum = MINER_OUTPUT_SCHEMA["properties"]["candidates"]["items"]["properties"]["trigger_type"]["enum"]
    assert set(enum) == {"command", "config", "callback", "event", "boot_phase", "unknown"}


def test_miner_user_message_includes_chunk_block_when_provided():
    """Chunked execution: each call gets an explicit assigned-
    candidates list. Per Part A of the system prompt the miner
    must emit one row per name in the chunk."""
    sys, user = build_miner_messages(_slice(), chunk=["foo", "bar", "baz"])
    assert "Assigned candidates" in user
    assert "- foo" in user
    assert "- bar" in user
    assert "- baz" in user


def test_miner_user_message_no_chunk_falls_back_to_full_set_instruction():
    """Backwards-compat: when no chunk is supplied (small projects
    / unit tests), the user message tells the miner to enumerate
    every candidate_function in the slice."""
    _, user = build_miner_messages(_slice())
    assert "no chunking" in user.lower() or "single-call" in user.lower()


def test_miner_system_forbids_skipping_assigned_candidates():
    """Part A guarantee: every assigned candidate gets a row, even
    if the miner doubts the entrypoint claim. Selection is the
    verifier's job."""
    sys, _ = build_miner_messages(_slice())
    text = sys.lower()
    # The prompt should explicitly call out that skipping is not
    # permitted and the verifier handles weak claims.
    assert "skipping is not permitted" in text or "skipping is not\n  permitted" in text


def test_miner_system_includes_part_b_discovery_instruction():
    """Part B guarantee: every chunk's call gets the discovery
    instruction so cross-chunk indexed-dispatch patterns are not
    dropped by chunking."""
    sys, _ = build_miner_messages(_slice())
    text = sys.lower()
    assert "indexed-dispatch" in text or "indexed dispatch" in text
    assert "discovery" in text


# --------- candidate_for_verifier (anchoring prevention!) ------------


def test_candidate_for_verifier_strips_reachability_text():
    """The miner's reachability prose must NOT travel to the verifier."""
    cand = {
        "id": "EP-001",
        "function": "f",
        "file": "x.c",
        "line": 1,
        "trigger_type": "callback",
        "trigger_ref": "trust_boundaries[function=f]",
        "supporting_substrate_edges": ["trust_boundaries[function=f]"],
        "reachability": "DETAILED MINER REASONING",
        "attacker_controllability": "MINER REASONING ABOUT CONTROL",
        "uncertainty": "MINER UNCERTAINTY TEXT",
        "confidence": "high",
    }
    stripped = candidate_for_verifier(cand)
    assert "reachability" not in stripped
    assert "attacker_controllability" not in stripped
    assert "uncertainty" not in stripped
    # Structural fields preserved.
    assert stripped["id"] == "EP-001"
    assert stripped["function"] == "f"
    assert stripped["trigger_type"] == "callback"
    assert stripped["supporting_substrate_edges"] == ["trust_boundaries[function=f]"]


def test_candidate_for_verifier_does_not_mutate_input():
    cand = {
        "id": "EP-001", "function": "f", "file": "x.c",
        "reachability": "REASONING",
    }
    candidate_for_verifier(cand)
    assert "reachability" in cand  # untouched


# --------- verifier ------------


def test_verifier_message_does_not_contain_miner_reasoning():
    """Build the verifier prompt with the miner-stripped candidate
    (the runner does this) and confirm none of the miner's prose
    leaks in."""
    miner_cand = {
        "id": "EP-001", "function": "f", "file": "x.c", "line": 1,
        "trigger_type": "callback", "trigger_ref": "trust_boundaries[function=f]",
        "supporting_substrate_edges": ["trust_boundaries[function=f]"],
        "reachability": "MINER_REACHABILITY_PROSE",
        "attacker_controllability": "MINER_CONTROLLABILITY_PROSE",
        "uncertainty": "MINER_UNCERTAINTY_TEXT",
        "confidence": "high",
    }
    structural = candidate_for_verifier(miner_cand)
    sys, user = build_verifier_messages(_slice(), structural)
    assert "MINER_REACHABILITY_PROSE" not in user
    assert "MINER_CONTROLLABILITY_PROSE" not in user
    assert "MINER_UNCERTAINTY_TEXT" not in user
    # But structural facts are present.
    assert '"function": "f"' in user
    assert '"trigger_type": "callback"' in user


def test_verifier_system_warns_about_anchoring():
    sys, _ = build_verifier_messages(_slice(), {"id": "EP-001"})
    sys_low = sys.lower()
    assert "independent" in sys_low or "independently" in sys_low
    assert "do not see" in sys_low or "withheld" in sys_low or "not see" in sys_low


def test_verifier_system_lists_critique_fields():
    sys, _ = build_verifier_messages(_slice(), {"id": "EP-001"})
    for field in ("reachability", "attacker_controllability",
                   "assumptions", "supporting_substrate_edges",
                   "refuting_substrate_edges", "verdict"):
        assert field in sys, f"verifier system prompt missing {field!r}"


def test_verifier_schema_enumerates_verdicts():
    enum = VERIFIER_OUTPUT_SCHEMA["properties"]["verdict"]["enum"]
    assert set(enum) == {"kept", "quarantined"}


def test_verifier_schema_requires_assumptions_array():
    req = VERIFIER_OUTPUT_SCHEMA["required"]
    assert "assumptions" in req
    assert "supporting_substrate_edges" in req
    assert "refuting_substrate_edges" in req
