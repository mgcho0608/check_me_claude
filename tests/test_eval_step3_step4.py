"""Tests for Step 3 IR + Step 4 scenario matchers — structural
overlap scoring + LLM judge with a stubbed ``chat_fn``.

The judge is exercised as a black box that returns a canned
verdict per call. The matcher logic (candidate ranking, top-K
selection, best-verdict roll-up) is what we verify.
"""

from __future__ import annotations

import json
from typing import Any

from check_me.eval import step3_match, step4_match
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


class _CannedJudge:
    """``chat_fn`` substitute that returns a canned verdict per
    call. Tests can pass a dict mapping a (gold_id, ours_id) hint
    to a verdict to make the response depend on which pair is
    being judged. Default is ``different``."""

    def __init__(self, default_verdict: str = "different",
                 by_pair: dict[tuple[str, str], str] | None = None):
        self.default = default_verdict
        self.by_pair = by_pair or {}
        self.calls: list[dict[str, Any]] = []

    def __call__(self, client, config, request: ChatRequest) -> ChatResponse:
        # Pull gold and ours ids from the user message JSON blocks.
        msg = request.messages[-1]["content"]
        verdict = self.default
        for (gid, oid), v in self.by_pair.items():
            if f'"id": "{gid}"' in msg and f'"id": "{oid}"' in msg:
                verdict = v
                break
        self.calls.append({"gold_id_hint": "gold" in msg.lower()})
        return _resp({
            "verdict": verdict,
            "confidence": "high",
            "reason": f"stub verdict {verdict}",
        })


def _ir(id_, entry_fn, sink_fn=None, sink_file="x.c", sink_line=10,
        intermediates=None):
    nodes = [{"function": entry_fn, "file": "src/main.c", "line": 1, "role": "entry"}]
    for fn in (intermediates or []):
        nodes.append({"function": fn, "file": "src/main.c", "line": 5, "role": "intermediate"})
    if sink_fn:
        nodes.append({"function": sink_fn, "file": sink_file, "line": sink_line,
                      "role": "sink"})
    return {
        "id": id_,
        "entrypoint": {"function": entry_fn, "file": "src/main.c", "line": 1},
        "runtime_context": {"trigger_type": "callback"},
        "path": {"nodes": nodes, "edges": []},
        "conditions": {"required": [], "blocking": []},
        "evidence_anchors": [],
        "confidence": "high",
        "uncertainty": "",
    }


def _irs_doc(irs):
    return {"schema_version": "v1", "project": "p", "cve": "CVE-X",
            "evidence_irs": irs}


# --------------------------------------------------------------------------- #
# Step 3 matcher
# --------------------------------------------------------------------------- #


def test_step3_no_candidate_when_no_overlap():
    gold = _irs_doc([_ir("IR-001", "entry_a", "sink_a")])
    ours = _irs_doc([_ir("IR-099", "totally_unrelated", "wrong_sink")])
    judge = _CannedJudge(default_verdict="different")
    rep = step3_match.match_irs(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    assert rep.matches[0].best_verdict == "no_candidate"
    # No judge call when there are no candidates.
    assert judge.calls == []


def test_step3_candidate_with_matching_entry_function_is_judged():
    gold = _irs_doc([_ir("IR-001", "entry_a", "sink_a")])
    ours = _irs_doc([_ir("IR-001", "entry_a", "sink_a")])
    judge = _CannedJudge(default_verdict="same")
    rep = step3_match.match_irs(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    assert rep.matches[0].best_verdict == "same"
    assert rep.matches[0].matched_ir_id == "IR-001"
    assert rep.same_count == 1


def test_step3_partial_verdict_recorded():
    gold = _irs_doc([_ir("IR-001", "entry_a", sink_fn="sink_a",
                         intermediates=["mid_a"])])
    ours = _irs_doc([_ir("IR-009", "entry_a", sink_fn=None,
                          intermediates=["mid_a"])])  # ends without real sink
    judge = _CannedJudge(default_verdict="partial")
    rep = step3_match.match_irs(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    assert rep.matches[0].best_verdict == "partial"
    assert rep.partial_count == 1
    # equivalent_recall counts same+partial as recovered.
    assert rep.equivalent_recall == 1.0


def test_step3_picks_best_verdict_from_top_k():
    """Two candidates: one ranks higher on structural overlap
    but the judge calls it ``different``; the second has lower
    overlap but ``same``. Matcher picks ``same`` regardless of
    ranking position."""
    gold = _irs_doc([_ir("IR-001", "entry_a", sink_fn="sink_a")])
    ours = _irs_doc([
        # Higher structural overlap but judged different.
        _ir("IR-100", "entry_a", sink_fn="sink_a"),
        # Lower overlap but judged same.
        _ir("IR-200", "entry_a", sink_fn=None),
    ])
    judge = _CannedJudge(by_pair={
        ("IR-001", "IR-100"): "different",
        ("IR-001", "IR-200"): "same",
    }, default_verdict="different")
    rep = step3_match.match_irs(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
        top_k_candidates=3,
    )
    assert rep.matches[0].best_verdict == "same"
    assert rep.matches[0].matched_ir_id == "IR-200"


def test_step3_judge_failure_falls_back_to_different():
    gold = _irs_doc([_ir("IR-001", "entry_a", sink_fn="sink_a")])
    ours = _irs_doc([_ir("IR-099", "entry_a", sink_fn="sink_a")])

    def boom(client, config, request: ChatRequest) -> ChatResponse:
        raise RuntimeError("simulated judge failure")

    rep = step3_match.match_irs(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=boom,
    )
    assert rep.matches[0].best_verdict == "different"
    assert "judge call failed" in rep.matches[0].judge_reason


# --------------------------------------------------------------------------- #
# Step 4 matcher
# --------------------------------------------------------------------------- #


def _scenario(id_, sink_fn="sink_a", sink_file="x.c", sink_type="memory_write",
              impact="memory_corruption", expl="high", ir_ids=("IR-001",)):
    return {
        "id": id_,
        "title": f"scenario {id_}",
        "exploit_chain": {
            "steps": [
                {"order": i + 1, "evidence_ir": ir, "action": "act", "result": "res"}
                for i, ir in enumerate(ir_ids)
            ],
        },
        "sink": {"function": sink_fn, "file": sink_file, "line": 42,
                 "evidence_ir_id": ir_ids[0], "sink_type": sink_type},
        "impact": {"category": impact, "description": "..."},
        "verdict": {"exploitability": expl, "reason": "..."},
        "confidence": "high", "uncertainty": "",
    }


def _as_doc(scs):
    return {"schema_version": "v1", "project": "p", "cve": "CVE-X",
            "attack_scenarios": scs}


def test_step4_perfect_match_records_all_structural_flags():
    gold = _as_doc([_scenario("AS-001")])
    ours = _as_doc([_scenario("AS-001")])
    judge = _CannedJudge(default_verdict="same")
    rep = step4_match.match_scenarios(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    m = rep.matches[0]
    assert m.best_verdict == "same"
    assert m.sink_function_match
    assert m.sink_type_match
    assert m.impact_category_match
    assert m.exploitability_match
    assert m.shared_ir_ids_count == 1


def test_step4_sink_function_recall_is_independent_of_count():
    """gold has 2 scenarios; ours has 4. As long as for each gold
    one we find an ours scenario with matching sink function, the
    recall is 1.0."""
    gold = _as_doc([
        _scenario("AS-001", sink_fn="add_resource_record"),
        _scenario("AS-002", sink_fn="add_resource_record"),
    ])
    ours = _as_doc([
        _scenario("AS-099", sink_fn="add_resource_record"),
        _scenario("AS-100", sink_fn="other_thing"),
        _scenario("AS-101", sink_fn="add_resource_record"),
        _scenario("AS-102", sink_fn="something_else"),
    ])
    judge = _CannedJudge(default_verdict="same")
    rep = step4_match.match_scenarios(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    assert rep.sink_function_recall == 1.0
    assert rep.same_count == 2


def test_step4_no_candidate_when_overlap_zero():
    gold = _as_doc([_scenario("AS-001", sink_fn="aaa", sink_type="memory_write",
                              impact="memory_corruption", expl="high",
                              ir_ids=("IR-001",))])
    ours = _as_doc([_scenario("AS-099", sink_fn="zzz", sink_type="auth_bypass",
                               impact="privilege_bypass", expl="low",
                               ir_ids=("IR-999",))])
    judge = _CannedJudge(default_verdict="same")
    rep = step4_match.match_scenarios(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    # No structural overlap → 0 candidates → no_candidate verdict.
    assert rep.matches[0].best_verdict == "no_candidate"
    assert judge.calls == []


def test_step4_partial_when_sink_function_matches_but_judge_disagrees():
    """Judge can override structural appearance."""
    gold = _as_doc([_scenario("AS-001", sink_fn="x", sink_type="memory_write")])
    ours = _as_doc([_scenario("AS-099", sink_fn="x", sink_type="memory_read")])
    judge = _CannedJudge(default_verdict="partial")
    rep = step4_match.match_scenarios(
        gold, ours, judge_client="x", judge_config=_cfg(), chat_fn=judge,
    )
    assert rep.matches[0].best_verdict == "partial"
    assert rep.matches[0].sink_function_match
    assert not rep.matches[0].sink_type_match
