"""Step 3 Evidence IR matcher — structural + LLM-judged.

For each gold IR, find the candidate IR(s) in our output that
look most likely to describe the same execution path, then run
the LLM judge on each candidate. The "best" match per gold IR is
the candidate with verdict ``same`` (preferred) or ``partial``
with the highest structural overlap.

Candidate selection (deterministic):
  - ``ours`` IRs whose entrypoint function matches gold's,
  - or ``ours`` IRs whose path nodes share at least 2 (function,
    file) pairs with gold's path,
  - or ``ours`` IRs that contain a ``role: sink`` node whose
    function matches a gold sink node's.

Top-K candidates by structural-overlap score are sent to the
judge; K defaults to 3 to bound LLM cost.

Per-gold-IR report:
  - best_verdict: same | partial | different | no_candidate
  - matched_ir_id: which of our IRs got the verdict
  - structural_node_overlap: |gold_nodes ∩ ours_nodes|
                              by (function, file)
  - judge_reason: free text from the judge
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat
from ..llm.config import Config
from . import judge as judge_mod


@dataclass
class IRMatchEntry:
    gold_ir_id: str
    gold_entry_function: str
    gold_sink_functions: list[str]
    matched_ir_id: str | None = None
    best_verdict: str = "no_candidate"
    judge_confidence: str = ""
    judge_reason: str = ""
    structural_node_overlap: int = 0
    candidates_considered: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "gold_ir_id": self.gold_ir_id,
            "gold_entry": self.gold_entry_function,
            "gold_sinks": list(self.gold_sink_functions),
            "matched_ir_id": self.matched_ir_id,
            "verdict": self.best_verdict,
            "judge_confidence": self.judge_confidence,
            "structural_node_overlap": self.structural_node_overlap,
            "candidates_considered": self.candidates_considered,
            "judge_reason": self.judge_reason[:300],
        }


@dataclass
class IRReport:
    project: str
    cve: str
    gold_ir_count: int = 0
    our_ir_count: int = 0
    matches: list[IRMatchEntry] = field(default_factory=list)

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
        """Treat ``same`` and ``partial`` as recovered (the gold
        IR's chain is at least partially in our output)."""
        if not self.gold_ir_count:
            return 1.0
        return (self.same_count + self.partial_count) / self.gold_ir_count

    def to_json(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "cve": self.cve,
            "gold_ir_count": self.gold_ir_count,
            "our_ir_count": self.our_ir_count,
            "verdict_counts": {
                "same": self.same_count,
                "partial": self.partial_count,
                "different": self.different_count,
                "no_candidate": self.no_candidate_count,
            },
            "equivalent_recall": round(self.equivalent_recall, 4),
            "matches": [m.to_json() for m in self.matches],
        }


def _node_keys(ir: dict[str, Any]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for n in (ir.get("path", {}).get("nodes") or []):
        f, file = n.get("function"), n.get("file")
        if isinstance(f, str) and isinstance(file, str):
            out.add((f, file))
    return out


def _sink_functions(ir: dict[str, Any]) -> list[str]:
    return [
        n.get("function") for n in (ir.get("path", {}).get("nodes") or [])
        if n.get("role") == "sink" and isinstance(n.get("function"), str)
    ]


def _entry_function(ir: dict[str, Any]) -> str | None:
    ep = ir.get("entrypoint", {}) or {}
    fn = ep.get("function")
    return fn if isinstance(fn, str) else None


def _candidate_overlap_score(
    gold_ir: dict[str, Any],
    our_ir: dict[str, Any],
) -> int:
    """Higher = more likely to be the same chain. Counts:
      +5 if entry functions match
      +3 per shared sink-role function
      +1 per shared (function, file) node pair
    """
    score = 0
    gef = _entry_function(gold_ir)
    oef = _entry_function(our_ir)
    if gef and gef == oef:
        score += 5
    g_sinks = set(_sink_functions(gold_ir))
    o_sinks = set(_sink_functions(our_ir))
    score += 3 * len(g_sinks & o_sinks)
    score += len(_node_keys(gold_ir) & _node_keys(our_ir))
    return score


def match_irs(
    gold: dict[str, Any],
    ours: dict[str, Any],
    *,
    judge_client: Any,
    judge_config: Config,
    top_k_candidates: int = 3,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> IRReport:
    """Match each gold IR to the best candidate IR in ours by
    structural overlap, then judge the top-K candidates with the
    LLM. Returns one ``IRMatchEntry`` per gold IR.

    Tests can pass a stub ``chat_fn`` that returns canned judge
    verdicts so the matcher logic is exercised without a live
    LLM call.
    """
    project = gold.get("project") or ours.get("project") or "<unknown>"
    cve = gold.get("cve") or ours.get("cve") or "<unknown>"

    gold_irs = list(gold.get("evidence_irs", []))
    our_irs = list(ours.get("evidence_irs", []))
    rep = IRReport(
        project=project, cve=cve,
        gold_ir_count=len(gold_irs), our_ir_count=len(our_irs),
    )

    for g in gold_irs:
        entry = IRMatchEntry(
            gold_ir_id=str(g.get("id", "?")),
            gold_entry_function=_entry_function(g) or "?",
            gold_sink_functions=_sink_functions(g),
        )
        # Rank candidates by structural overlap.
        scored = sorted(
            ((_candidate_overlap_score(g, o), o) for o in our_irs),
            key=lambda p: -p[0],
        )
        candidates = [o for s, o in scored[:top_k_candidates] if s > 0]
        entry.candidates_considered = len(candidates)
        if not candidates:
            rep.matches.append(entry)
            continue

        # Judge each top candidate; pick best verdict.
        best_verdict_rank = {"same": 3, "partial": 2, "different": 1}
        best = None
        for cand in candidates:
            try:
                v = judge_mod.judge_pair(
                    client=judge_client, config=judge_config,
                    artefact_kind="Evidence IR",
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
            entry.matched_ir_id = str(cand.get("id", "?"))
            entry.best_verdict = vp.get("verdict", "different")
            entry.judge_confidence = vp.get("confidence", "")
            entry.judge_reason = vp.get("reason", "")
            entry.structural_node_overlap = len(
                _node_keys(g) & _node_keys(cand)
            )
        rep.matches.append(entry)

    return rep
