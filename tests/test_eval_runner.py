"""End-to-end eval runner test with stubbed judge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.eval import runner as eval_runner
from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config


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


def _empty_substrate():
    return {
        "schema_version": "v1", "project": "p", "cve": "CVE-X",
        "categories": {
            "call_graph": [], "data_control_flow": [], "guards": [],
            "trust_boundaries": [], "config_mode_command_triggers": [],
            "callback_registrations": [], "evidence_anchors": [],
        },
    }


def _ep_doc(entries):
    return {"schema_version": "v1", "project": "p", "cve": "CVE-X",
            "entrypoints": entries}


def _irs_doc(irs):
    return {"schema_version": "v1", "project": "p", "cve": "CVE-X",
            "evidence_irs": irs}


def _as_doc(scs):
    return {"schema_version": "v1", "project": "p", "cve": "CVE-X",
            "attack_scenarios": scs}


def _ir(id_, entry_fn, sink_fn=None):
    nodes = [{"function": entry_fn, "file": "x.c", "line": 1, "role": "entry"}]
    if sink_fn:
        nodes.append({"function": sink_fn, "file": "x.c", "line": 10, "role": "sink"})
    return {
        "id": id_,
        "entrypoint": {"function": entry_fn, "file": "x.c", "line": 1},
        "runtime_context": {"trigger_type": "callback"},
        "path": {"nodes": nodes, "edges": []},
        "conditions": {"required": [], "blocking": []},
        "evidence_anchors": [],
        "confidence": "high", "uncertainty": "",
    }


def _scenario(id_="AS-001", sink_fn="sink_a"):
    return {
        "id": id_, "title": "t",
        "exploit_chain": {"steps": [{"order": 1, "evidence_ir": "IR-001",
                                      "action": "a", "result": "r"}]},
        "sink": {"function": sink_fn, "file": "x.c", "line": 10,
                 "evidence_ir_id": "IR-001", "sink_type": "memory_write"},
        "impact": {"category": "memory_corruption", "description": "..."},
        "verdict": {"exploitability": "high", "reason": "..."},
        "confidence": "high", "uncertainty": "",
    }


def _setup_dataset(tmp_path: Path):
    gold = tmp_path / "gold"
    out = tmp_path / "out"
    gold.mkdir(); out.mkdir()

    sub = _empty_substrate()
    (gold / "substrate.json").write_text(json.dumps(sub))
    (out / "substrate.json").write_text(json.dumps(sub))

    ep = _ep_doc([{"id": "EP-001", "function": "entry_a", "file": "x.c",
                    "status": "kept", "trigger_type": "callback",
                    "confidence": "high"}])
    (gold / "entrypoints.json").write_text(json.dumps(ep))
    (out / "entrypoints.json").write_text(json.dumps(ep))

    irs = _irs_doc([_ir("IR-001", "entry_a", "sink_a")])
    (gold / "evidence_irs.json").write_text(json.dumps(irs))
    (out / "evidence_irs.json").write_text(json.dumps(irs))

    scs = _as_doc([_scenario()])
    (gold / "attack_scenarios.json").write_text(json.dumps(scs))
    (out / "attack_scenarios.json").write_text(json.dumps(scs))

    return gold, out


def _stub_judge_same():
    def fn(client, config, request: ChatRequest) -> ChatResponse:
        return _resp({"verdict": "same", "confidence": "high",
                       "reason": "stub same"})
    return fn


def test_runner_end_to_end_perfect_match(tmp_path):
    gold, out = _setup_dataset(tmp_path)
    rep = eval_runner.run(
        gold_dir=gold, out_dir=out,
        eval_report_path=tmp_path / "eval_report.json",
        judge_config=_cfg(), judge_client="stub",
        chat_fn=_stub_judge_same(),
    )
    assert rep.step1["overall_recall"] == 1.0
    assert rep.step2["gold_kept_recall_kept_only"] == 1.0
    assert rep.step3["equivalent_recall"] == 1.0
    assert rep.step4["equivalent_recall"] == 1.0
    # Exit criteria all pass.
    assert rep.exit_criteria["all_pass"]
    # Eval report file written.
    saved = json.loads((tmp_path / "eval_report.json").read_text())
    assert saved["project"] == "p"


def test_runner_skip_step3_step4(tmp_path):
    gold, out = _setup_dataset(tmp_path)
    rep = eval_runner.run(
        gold_dir=gold, out_dir=out,
        skip_step3=True, skip_step4=True,
        judge_config=_cfg(), judge_client="stub",
        chat_fn=_stub_judge_same(),
    )
    assert rep.step1["overall_recall"] == 1.0
    assert rep.step3 == {} or rep.step3.get("skipped")
    assert rep.step4 == {} or rep.step4.get("skipped")


def test_runner_exit_criteria_fail_when_recall_low(tmp_path):
    gold, out = _setup_dataset(tmp_path)
    # Drop our gold kept entry from out/entrypoints.json so
    # gold_kept_anywhere_recall = 0.
    o_ep = json.loads((out / "entrypoints.json").read_text())
    o_ep["entrypoints"] = []
    (out / "entrypoints.json").write_text(json.dumps(o_ep))

    rep = eval_runner.run(
        gold_dir=gold, out_dir=out,
        skip_step3=True, skip_step4=True,
        judge_config=_cfg(), judge_client="stub",
        chat_fn=_stub_judge_same(),
    )
    ec = rep.exit_criteria
    assert ec["EC-2_step2_gold_kept_anywhere_recall>=0.8"][0] is False
    assert not ec["all_pass"]
