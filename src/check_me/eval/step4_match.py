"""Step 4 attack-scenario matcher — structural enums + LLM judge.

Per gold scenario, find the candidate scenario(s) in our output
that look most likely to describe the same vulnerability, then
run the LLM judge on each top candidate. Structural pre-filter:

  +6 if gold ``sink.function`` matches an ``ours`` scenario's
       sink.function
  +3 if gold ``sink.sink_type`` matches ours
  +3 if gold ``impact.category`` matches ours
  +1 if gold ``verdict.exploitability`` matches ours
  +1 per IR id shared between gold's and ours's exploit_chain steps
       (when our IRs and gold IRs cross-reference the same chain)

Top-K (default 3) candidates by score go to the LLM judge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from . import judge as judge_mod


@dataclass
class ScenarioMatchEntry:
    gold_scenario_id: str
    gold_sink_function: str
    gold_sink_type: str
    gold_impact_category: str
    matched_scenario_id: str | None = None
    best_verdict: str = "no_candidate"
    judge_confidence: str = ""
    judge_reason: str = ""
    sink_function_match: bool = False
    sink_type_match: bool = False
    impact_category_match: bool = False
    exploitability_match: bool = False
    shared_ir_ids_count: int = 0
    candidates_considered: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "gold_scenario_id": self.gold_scenario_id,
            "gold_sink_function": self.gold_sink_function,
            "gold_sink_type": self.gold_sink_type,
            "gold_impact_category": self.gold_impact_category,
            "matched_scenario_id": self.matched_scenario_id,
            "verdict": self.best_verdict,
            "judge_confidence": self.judge_confidence,
            "structural": {
                "sink_function_match": self.sink_function_match,
                "sink_type_match": self.sink_type_match,
                "impact_category_match": self.impact_category_match,
                "exploitability_match": self.exploitability_match,
                "shared_ir_ids_count": self.shared_ir_ids_count,
            },
            "candidates_considered": self.candidates_considered,
            "judge_reason": self.judge_reason[:300],
        }


@dataclass
class ScenarioReport:
    project: str
    cve: str
    gold_scenario_count: int = 0
    our_scenario_count: int = 0
    matches: list[ScenarioMatchEntry] = field(default_factory=list)

    @property
    def same_count(self) -> int:
        return sum(1 for m in self.matches if m.best_verdict == "same")

    @property
    def partial_count(self) -> int:
        return sum(1 for m in self.matches if m.best_verdict == "partial")

    @property
    def different_count(self) -> int:
        return sum(1 for m in self.matches if m.best_verdict == "different")

    @property
    def no_candidate_count(self) -> int:
        return sum(1 for m in self.matches if m.best_verdict == "no_candidate")

    @property
    def equivalent_recall(self) -> float:
        if not self.gold_scenario_count:
            return 1.0
        return (self.same_count + self.partial_count) / self.gold_scenario_count

    @property
    def sink_function_recall(self) -> float:
        """Headline: did our pipeline produce a scenario whose
        sink function matches any gold scenario's? Tolerant of
        scenario count mismatch."""
        if not self.gold_scenario_count:
            return 1.0
        return (
            sum(1 for m in self.matches if m.sink_function_match)
            / self.gold_scenario_count
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "cve": self.cve,
            "gold_scenario_count": self.gold_scenario_count,
            "our_scenario_count": self.our_scenario_count,
            "verdict_counts": {
                "same": self.same_count,
                "partial": self.partial_count,
                "different": self.different_count,
                "no_candidate": self.no_candidate_count,
            },
            "equivalent_recall": round(self.equivalent_recall, 4),
            "sink_function_recall": round(self.sink_function_recall, 4),
            "matches": [m.to_json() for m in self.matches],
        }


def _ir_ids_in_chain(sc: dict[str, Any]) -> set[str]:
    return {
        s.get("evidence_ir") for s in (sc.get("exploit_chain", {}).get("steps") or [])
        if isinstance(s.get("evidence_ir"), str)
    }


def _scenario_overlap_score(
    gold: dict[str, Any],
    ours: dict[str, Any],
) -> int:
    score = 0
    g_sink = gold.get("sink", {}) or {}
    o_sink = ours.get("sink", {}) or {}
    g_imp = gold.get("impact", {}) or {}
    o_imp = ours.get("impact", {}) or {}
    g_v = gold.get("verdict", {}) or {}
    o_v = ours.get("verdict", {}) or {}
    if (
        isinstance(g_sink.get("function"), str)
        and g_sink.get("function") == o_sink.get("function")
    ):
        score += 6
    if (
        isinstance(g_sink.get("sink_type"), str)
        and g_sink.get("sink_type") == o_sink.get("sink_type")
    ):
        score += 3
    if (
        isinstance(g_imp.get("category"), str)
        and g_imp.get("category") == o_imp.get("category")
    ):
        score += 3
    if (
        isinstance(g_v.get("exploitability"), str)
        and g_v.get("exploitability") == o_v.get("exploitability")
    ):
        score += 1
    score += len(_ir_ids_in_chain(gold) & _ir_ids_in_chain(ours))
    return score


def match_scenarios(
    gold: dict[str, Any],
    ours: dict[str, Any],
    *,
    judge_client: Any,
    judge_config: Config,
    top_k_candidates: int = 3,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> ScenarioReport:
    project = gold.get("project") or ours.get("project") or "<unknown>"
    cve = gold.get("cve") or ours.get("cve") or "<unknown>"

    gold_scs = list(gold.get("attack_scenarios", []))
    our_scs = list(ours.get("attack_scenarios", []))
    rep = ScenarioReport(
        project=project, cve=cve,
        gold_scenario_count=len(gold_scs), our_scenario_count=len(our_scs),
    )

    for g in gold_scs:
        g_sink = g.get("sink", {}) or {}
        g_imp = g.get("impact", {}) or {}
        entry = ScenarioMatchEntry(
            gold_scenario_id=str(g.get("id", "?")),
            gold_sink_function=str(g_sink.get("function") or "?"),
            gold_sink_type=str(g_sink.get("sink_type") or "?"),
            gold_impact_category=str(g_imp.get("category") or "?"),
        )

        scored = sorted(
            ((_scenario_overlap_score(g, o), o) for o in our_scs),
            key=lambda p: -p[0],
        )
        candidates = [o for s, o in scored[:top_k_candidates] if s > 0]
        entry.candidates_considered = len(candidates)
        if not candidates:
            rep.matches.append(entry)
            continue

        best_verdict_rank = {"same": 3, "partial": 2, "different": 1}
        best = None
        for cand in candidates:
            try:
                v = judge_mod.judge_pair(
                    client=judge_client, config=judge_config,
                    artefact_kind="attack scenario",
                    project=project, cve=cve,
                    gold=g, ours=cand,
                    chat_fn=chat_fn,
                )
                vp = v.parsed
            except Exception as exc:  # noqa: BLE001
                vp = {
                    "verdict": "different",
                    "confidence": "low",
                    "reason": f"judge call failed: {type(exc).__name__}: {exc}",
                }
            rank = best_verdict_rank.get(vp.get("verdict", "different"), 0)
            if best is None or rank > best[0]:
                best = (rank, cand, vp)

        if best:
            _, cand, vp = best
            o_sink = cand.get("sink", {}) or {}
            o_imp = cand.get("impact", {}) or {}
            o_v = cand.get("verdict", {}) or {}
            entry.matched_scenario_id = str(cand.get("id", "?"))
            entry.best_verdict = vp.get("verdict", "different")
            entry.judge_confidence = vp.get("confidence", "")
            entry.judge_reason = vp.get("reason", "")
            entry.sink_function_match = (
                g_sink.get("function") == o_sink.get("function")
                and isinstance(g_sink.get("function"), str)
            )
            entry.sink_type_match = g_sink.get("sink_type") == o_sink.get("sink_type")
            entry.impact_category_match = g_imp.get("category") == o_imp.get("category")
            entry.exploitability_match = (
                (g.get("verdict", {}) or {}).get("exploitability")
                == o_v.get("exploitability")
            )
            entry.shared_ir_ids_count = len(
                _ir_ids_in_chain(g) & _ir_ids_in_chain(cand)
            )
        rep.matches.append(entry)

    return rep
