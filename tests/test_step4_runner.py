"""Tests for Step 4 attack scenario synthesis runner."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config
from check_me.step4 import runner as runner_mod


def _cfg():
    return Config(
        url="https://x.test/v1", key="k", model="m",
        temperature=0.0, max_tokens=4096,
    )


def _resp(obj) -> ChatResponse:
    s = json.dumps(obj)
    return ChatResponse(
        content=s, finish_reason="stop",
        prompt_tokens=10, completion_tokens=20, total_tokens=30,
        model="m", raw={"choices": [{"finish_reason": "stop",
                                      "message": {"content": s}}]},
    )


class _SeqChat:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, client, config, request: ChatRequest) -> ChatResponse:
        self.calls.append({"messages": list(request.messages)})
        if not self.responses:
            raise AssertionError("ran out of canned responses")
        return self.responses.pop(0)


def _scenario(id_="AS-001", ir_id="IR-001", sink_fn="vuln_func", sink_file="f.c"):
    return {
        "id": id_,
        "title": "Test scenario",
        "exploit_chain": {
            "steps": [
                {"order": 1, "evidence_ir": ir_id,
                 "action": "attacker sends crafted packet",
                 "result": "vuln_func executes with attacker bytes"},
            ],
        },
        "sink": {
            "function": sink_fn, "file": sink_file, "line": 42,
            "evidence_ir_id": ir_id, "sink_type": "memory_write",
        },
        "impact": {
            "category": "memory_corruption",
            "description": "1-byte heap overflow",
        },
        "verdict": {
            "exploitability": "high",
            "reason": "single network packet, no auth required",
        },
        "confidence": "high",
        "uncertainty": "",
    }


def _setup(tmp_path: Path, *, ir_with_sink: bool = True) -> dict[str, Path]:
    src = tmp_path / "source"
    src.mkdir()
    (src / "f.c").write_text(textwrap.dedent("""\
        #include <string.h>
        void vuln_func(char *dst, char *src) {
            // line 3 — unbounded copy
            strcpy(dst, src);
        }
    """))

    ir_node = {"function": "vuln_func", "file": "f.c", "line": 3,
               "role": "sink" if ir_with_sink else "intermediate"}
    irs_doc = {
        "schema_version": "v1",
        "project": "p", "cve": "CVE-T",
        "evidence_irs": [{
            "id": "IR-001",
            "entrypoint": {"function": "vuln_func", "file": "f.c", "line": 2},
            "runtime_context": {"trigger_type": "callback"},
            "path": {
                "nodes": [
                    {"function": "vuln_func", "file": "f.c", "line": 2,
                     "role": "entry"},
                    ir_node,
                ],
                "edges": [],
            },
            "conditions": {"required": [], "blocking": []},
            "evidence_anchors": [
                {"file": "f.c", "line_start": 3, "line_end": 3,
                 "note": "strcpy"},
            ],
            "confidence": "high",
            "uncertainty": "",
        }],
    }
    irs_path = tmp_path / "evidence_irs.json"
    irs_path.write_text(json.dumps(irs_doc))

    return {"irs": irs_path, "source": src}


def test_runner_emits_one_scenario_per_chain(tmp_path):
    paths = _setup(tmp_path)
    seq = _SeqChat([_resp({"attack_scenarios": [_scenario()]})])
    out, report = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub",
        chat_fn=seq,
    )
    assert len(out["attack_scenarios"]) == 1
    assert out["attack_scenarios"][0]["id"] == "AS-001"
    assert report.scenarios_produced == 1


def test_runner_extracts_sink_excerpts_and_passes_them_to_llm(tmp_path):
    paths = _setup(tmp_path, ir_with_sink=True)
    seq = _SeqChat([_resp({"attack_scenarios": [_scenario()]})])
    out, report = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub",
        chat_fn=seq,
    )
    user_msg = seq.calls[0]["messages"][-1]["content"]
    # The IR's sink file:line excerpt is included.
    assert "[f.c:" in user_msg, user_msg[:500]
    assert "strcpy" in user_msg
    assert report.irs_with_sinks == 1


def test_runner_skips_excerpt_when_ir_has_no_sink_node(tmp_path):
    paths = _setup(tmp_path, ir_with_sink=False)
    seq = _SeqChat([_resp({"attack_scenarios": []})])
    out, report = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub",
        chat_fn=seq,
    )
    assert report.irs_with_sinks == 0


def test_runner_assigns_global_sequential_ids(tmp_path):
    paths = _setup(tmp_path)
    seq = _SeqChat([_resp({"attack_scenarios": [
        _scenario(id_="LLM-said-X"),
        _scenario(id_="LLM-said-Y"),
    ]})])
    out, _ = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub",
        chat_fn=seq,
    )
    ids = [s["id"] for s in out["attack_scenarios"]]
    assert ids == ["AS-001", "AS-002"]


def test_runner_synthesis_failure_yields_empty_with_retry(tmp_path):
    """A raised synthesis error must NOT crash the run; the
    retry pass should attempt again."""
    paths = _setup(tmp_path)
    state = {"calls": 0}
    def flaky(client, config, request: ChatRequest) -> ChatResponse:
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("simulated transient")
        return _resp({"attack_scenarios": [_scenario()]})

    out, report = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=flaky,
        synth_retry_passes=1, synth_retry_cooldown_sec=0,
    )
    assert len(out["attack_scenarios"]) == 1
    assert report.synth_call.get("ok") is True
    assert report.synth_call.get("retry_pass") == 1


def test_runner_retry_exhausted_returns_empty_scenarios(tmp_path):
    paths = _setup(tmp_path)
    def always_fails(client, config, request: ChatRequest) -> ChatResponse:
        raise RuntimeError("simulated permanent")

    out, report = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=always_fails,
        synth_retry_passes=2, synth_retry_cooldown_sec=0,
    )
    assert out["attack_scenarios"] == []
    assert report.synth_call.get("ok") is False


def test_runner_validates_against_attack_scenarios_schema(tmp_path):
    """Round-trip the runner's output against
    schemas/attack_scenarios.v1.json so the schema and the
    runner stay in sync."""
    import jsonschema
    schema_path = Path(__file__).parents[1] / "schemas" / "attack_scenarios.v1.json"
    if not schema_path.is_file():
        pytest.skip("schemas/attack_scenarios.v1.json not present")
    schema = json.loads(schema_path.read_text())

    paths = _setup(tmp_path)
    seq = _SeqChat([_resp({"attack_scenarios": [_scenario()]})])
    out, _ = runner_mod.run(
        evidence_irs_path=paths["irs"],
        source_root=paths["source"],
        config=_cfg(), client="stub",
        chat_fn=seq,
    )
    jsonschema.validate(out, schema)
