"""Pytest for step2.runner — orchestration with stub LLM.

Verifies the runner's wiring without touching the network: a stubbed
``chat_fn`` returns canned miner / verifier responses, and the
runner is exercised end-to-end. The most important behavioural test
is anchoring prevention — the verifier call must not see the
miner's reachability prose.
"""

from __future__ import annotations

import json

import pytest

from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config
from check_me.step2 import runner as runner_mod


def _cfg():
    return Config(
        url="https://x.test/v1", key="k", model="m",
        temperature=0.1, max_tokens=4096,
    )


def _resp(content_obj) -> ChatResponse:
    content = json.dumps(content_obj)
    return ChatResponse(
        content=content,
        finish_reason="stop",
        prompt_tokens=10,
        completion_tokens=20,
        total_tokens=30,
        model="m",
        raw={
            "choices": [{"finish_reason": "stop",
                          "message": {"content": content}}],
        },
    )


class _SequencedChat:
    """chat_fn substitute that returns canned responses in order and
    records each call's request kwargs for later assertion."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, client, config, request: ChatRequest) -> ChatResponse:
        if not self.responses:
            raise AssertionError("ran out of canned responses")
        self.calls.append(
            {
                "client": client,
                "messages": list(request.messages),
                "json_object": request.json_object,
            }
        )
        return self.responses.pop(0)


def _empty_substrate():
    return {
        "schema_version": "v1",
        "project": "test_proj",
        "cve": "CVE-T",
        "categories": {
            "call_graph": [],
            "data_control_flow": [],
            "guards": [],
            "trust_boundaries": [
                {"kind": "network_socket", "function": "entry",
                 "file": "f.c", "line": 10,
                 "direction": "untrusted_to_trusted"},
            ],
            "config_mode_command_triggers": [],
            "callback_registrations": [],
            "evidence_anchors": [],
        },
    }


def _miner_response_one_kept_candidate():
    return {
        "candidates": [
            {
                "id": "EP-001",
                "function": "entry",
                "file": "f.c",
                "line": 10,
                "trigger_type": "event",
                "trigger_ref": "trust_boundaries[function=entry]",
                "reachability": "MINER_REACHABILITY_PROSE_DO_NOT_LEAK",
                "attacker_controllability": "MINER_CONTROL_PROSE_DO_NOT_LEAK",
                "supporting_substrate_edges": ["trust_boundaries[function=entry]"],
                "confidence": "high",
                "uncertainty": "MINER_UNCERTAINTY_DO_NOT_LEAK",
            }
        ]
    }


def _verifier_kept_response():
    return {
        "verdict": "kept",
        "reachability": "Verifier-independent reachability text",
        "attacker_controllability": "Verifier-independent controllability text",
        "assumptions": ["A1"],
        "supporting_substrate_edges": ["trust_boundaries[function=entry]"],
        "refuting_substrate_edges": [],
        "confidence": "high",
        "uncertainty": "Verifier uncertainty",
    }


def _verifier_quarantine_response():
    return {
        "verdict": "quarantined",
        "reachability": "Reachable only on a feature flag we have no evidence of",
        "attacker_controllability": "Speculative",
        "assumptions": [],
        "supporting_substrate_edges": [],
        "refuting_substrate_edges": ["call_graph[caller=entry] is empty"],
        "quarantine_reason": "Insufficient supporting substrate evidence.",
        "confidence": "medium",
        "uncertainty": "",
    }


# --------------------------------------------------------------------------- #
# Smoke
# --------------------------------------------------------------------------- #


def test_runner_emits_schema_v1_envelope():
    seq = _SequencedChat(
        [_resp(_miner_response_one_kept_candidate()),
         _resp(_verifier_kept_response())]
    )
    output, report = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="dummy_miner_client",
        verifier_client="dummy_verifier_client",
        chat_fn=seq,
    )
    assert output["schema_version"] == "v1"
    assert output["project"] == "test_proj"
    assert output["cve"] == "CVE-T"
    assert isinstance(output["entrypoints"], list)


def test_one_kept_candidate_round_trip():
    seq = _SequencedChat([
        _resp(_miner_response_one_kept_candidate()),
        _resp(_verifier_kept_response()),
    ])
    output, report = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    assert len(output["entrypoints"]) == 1
    e = output["entrypoints"][0]
    assert e["id"] == "EP-001"
    assert e["function"] == "entry"
    assert e["status"] == "kept"
    assert report.kept == 1
    assert report.quarantined == 0


# --------------------------------------------------------------------------- #
# Anchoring prevention — the headline test
# --------------------------------------------------------------------------- #


def test_verifier_call_does_not_see_miner_reasoning():
    """Critical invariant per PLAN §0 / Rule 2b: the miner's
    reachability / attacker_controllability / uncertainty prose must
    NOT travel to the verifier."""
    seq = _SequencedChat([
        _resp(_miner_response_one_kept_candidate()),
        _resp(_verifier_kept_response()),
    ])
    runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    # First call: miner. Second call: verifier.
    verifier_user_msg = seq.calls[1]["messages"][1]["content"]
    assert "MINER_REACHABILITY_PROSE_DO_NOT_LEAK" not in verifier_user_msg
    assert "MINER_CONTROL_PROSE_DO_NOT_LEAK" not in verifier_user_msg
    assert "MINER_UNCERTAINTY_DO_NOT_LEAK" not in verifier_user_msg
    # Structural facts ARE there.
    assert "EP-001" in verifier_user_msg
    assert "entry" in verifier_user_msg


def test_verifier_uses_separate_client_object():
    """A fresh client per session is the second half of anchoring
    prevention — no shared SDK-level conversation state."""
    seq = _SequencedChat([
        _resp(_miner_response_one_kept_candidate()),
        _resp(_verifier_kept_response()),
    ])
    runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="MINER_CLIENT_OBJ",
        verifier_client="VERIFIER_CLIENT_OBJ",
        chat_fn=seq,
    )
    assert seq.calls[0]["client"] == "MINER_CLIENT_OBJ"
    assert seq.calls[1]["client"] == "VERIFIER_CLIENT_OBJ"


# --------------------------------------------------------------------------- #
# Quarantine path
# --------------------------------------------------------------------------- #


def test_quarantine_verdict_recorded_with_reason():
    seq = _SequencedChat([
        _resp(_miner_response_one_kept_candidate()),
        _resp(_verifier_quarantine_response()),
    ])
    output, report = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    assert report.kept == 0
    assert report.quarantined == 1
    e = output["entrypoints"][0]
    assert e["status"] == "quarantined"
    assert "Insufficient supporting" in e["quarantine_reason"]


# --------------------------------------------------------------------------- #
# Multiple candidates → one verifier call per candidate
# --------------------------------------------------------------------------- #


def test_one_verifier_call_per_candidate():
    miner_response = {
        "candidates": [
            {**_miner_response_one_kept_candidate()["candidates"][0],
             "id": "EP-001", "function": "entry"},
            {**_miner_response_one_kept_candidate()["candidates"][0],
             "id": "EP-002", "function": "entry2"},
            {**_miner_response_one_kept_candidate()["candidates"][0],
             "id": "EP-003", "function": "entry3"},
        ]
    }
    seq = _SequencedChat([
        _resp(miner_response),
        _resp(_verifier_kept_response()),
        _resp(_verifier_quarantine_response()),
        _resp(_verifier_kept_response()),
    ])
    output, report = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    # 1 miner + 3 verifier = 4 calls.
    assert len(seq.calls) == 4
    assert report.candidates_proposed == 3
    assert report.kept == 2
    assert report.quarantined == 1


# --------------------------------------------------------------------------- #
# Schema validation (entrypoints.v1.json)
# --------------------------------------------------------------------------- #


def test_runner_output_validates_against_entrypoints_schema():
    import jsonschema
    from pathlib import Path
    schema_path = Path(__file__).parents[1] / "schemas" / "entrypoints.v1.json"
    if not schema_path.is_file():
        pytest.skip("schemas/entrypoints.v1.json not present")
    schema = json.loads(schema_path.read_text())

    seq = _SequencedChat([
        _resp(_miner_response_one_kept_candidate()),
        _resp(_verifier_kept_response()),
    ])
    output, _ = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    jsonschema.validate(output, schema)


# --------------------------------------------------------------------------- #
# Empty miner output
# --------------------------------------------------------------------------- #


def test_empty_miner_output_yields_empty_entrypoints():
    seq = _SequencedChat([_resp({"candidates": []})])
    output, report = runner_mod.run(
        _empty_substrate(),
        miner_config=_cfg(), verifier_config=_cfg(),
        miner_client="m", verifier_client="v",
        chat_fn=seq,
    )
    assert output["entrypoints"] == []
    assert report.candidates_proposed == 0
    # No verifier calls when no candidates.
    assert len(seq.calls) == 1
