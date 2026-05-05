"""Deterministic Step 2 entrypoint matcher.

Compares gold ``entrypoints.json`` against our pipeline's
``entrypoints.json``. Match key is ``function`` (the gold's
authoritative function name); ``file`` is recorded for context
but does not gate the match — same-name overloads across
translation units are treated as the same conceptual entrypoint
because gold's curated set typically picks one canonical row per
function.

Cross-tab cell values per gold function:

  * gold_kept ∩ our_kept           — true-positive (TP)
  * gold_kept ∩ our_quarantined    — soft-loss (verifier
                                      wrongly downgraded a real
                                      entrypoint to quarantine —
                                      recoverable per PLAN Rule 4)
  * gold_kept ∩ our_missing         — silent FN (substrate or
                                      Step 2 dropped a real
                                      entrypoint entirely)
  * gold_quarantined ∩ our_kept    — soft-extra (we promoted
                                      something gold considered
                                      borderline; not a failure)
  * gold_quarantined ∩ our_quar.   — match
  * gold_quarantined ∩ our_missing — extra-soft loss
  * our_kept ∩ no_gold              — FP candidate (extras —
                                      can be legitimate; gold is
                                      curated, not exhaustive)
  * our_quar. ∩ no_gold             — informational only

Exit-criterion-relevant headline metric: ``gold_kept_recall`` =
``gold_kept_in_our_kept`` / ``len(gold_kept)``. Drop into
``gold_kept ∩ our_quarantined`` is recorded separately so
operators can audit those cases.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EntrypointReport:
    project: str
    cve: str
    gold_kept_total: int = 0
    gold_quarantined_total: int = 0
    our_kept_total: int = 0
    our_quarantined_total: int = 0
    gold_kept_in_our_kept: int = 0
    gold_kept_in_our_quarantined: int = 0
    gold_kept_missing: int = 0
    gold_quarantined_in_our_kept: int = 0
    gold_quarantined_in_our_quarantined: int = 0
    gold_quarantined_missing: int = 0
    our_kept_no_gold: int = 0
    our_quarantined_no_gold: int = 0

    gold_kept_missing_examples: list[dict[str, Any]] = field(default_factory=list)
    gold_kept_in_our_quarantined_examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def gold_kept_recall(self) -> float:
        return (
            self.gold_kept_in_our_kept / self.gold_kept_total
            if self.gold_kept_total else 1.0
        )

    @property
    def gold_kept_in_our_anywhere(self) -> int:
        return self.gold_kept_in_our_kept + self.gold_kept_in_our_quarantined

    @property
    def gold_kept_anywhere_recall(self) -> float:
        """Recall counting both kept and quarantined as 'we have
        the function'. PLAN Rule 4 says quarantined is auditable
        — it's a softer match but the function is preserved."""
        return (
            self.gold_kept_in_our_anywhere / self.gold_kept_total
            if self.gold_kept_total else 1.0
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "cve": self.cve,
            "totals": {
                "gold_kept": self.gold_kept_total,
                "gold_quarantined": self.gold_quarantined_total,
                "our_kept": self.our_kept_total,
                "our_quarantined": self.our_quarantined_total,
            },
            "gold_kept_recall_kept_only": round(self.gold_kept_recall, 4),
            "gold_kept_recall_anywhere": round(self.gold_kept_anywhere_recall, 4),
            "cross_tab": {
                "gold_kept_in_our_kept": self.gold_kept_in_our_kept,
                "gold_kept_in_our_quarantined": self.gold_kept_in_our_quarantined,
                "gold_kept_missing": self.gold_kept_missing,
                "gold_quarantined_in_our_kept": self.gold_quarantined_in_our_kept,
                "gold_quarantined_in_our_quarantined": self.gold_quarantined_in_our_quarantined,
                "gold_quarantined_missing": self.gold_quarantined_missing,
                "our_kept_no_gold": self.our_kept_no_gold,
                "our_quarantined_no_gold": self.our_quarantined_no_gold,
            },
            "diagnostics": {
                "gold_kept_missing_examples": self.gold_kept_missing_examples[:5],
                "gold_kept_in_our_quarantined_examples":
                    self.gold_kept_in_our_quarantined_examples[:5],
            },
        }


def _index_by_function(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in entries:
        fn = e.get("function")
        if isinstance(fn, str) and fn:
            out[fn].append(e)
    return out


def match_entrypoints(
    gold: dict[str, Any],
    ours: dict[str, Any],
) -> EntrypointReport:
    project = gold.get("project") or ours.get("project") or "<unknown>"
    cve = gold.get("cve") or ours.get("cve") or "<unknown>"

    g_entries = list(gold.get("entrypoints", []))
    o_entries = list(ours.get("entrypoints", []))

    g_kept = [e for e in g_entries if e.get("status") == "kept"]
    g_quar = [e for e in g_entries if e.get("status") == "quarantined"]
    o_kept = [e for e in o_entries if e.get("status") == "kept"]
    o_quar = [e for e in o_entries if e.get("status") == "quarantined"]

    rep = EntrypointReport(
        project=project, cve=cve,
        gold_kept_total=len(g_kept),
        gold_quarantined_total=len(g_quar),
        our_kept_total=len(o_kept),
        our_quarantined_total=len(o_quar),
    )

    o_kept_idx = _index_by_function(o_kept)
    o_quar_idx = _index_by_function(o_quar)

    for ge in g_kept:
        fn = ge.get("function")
        if not isinstance(fn, str):
            continue
        if fn in o_kept_idx:
            rep.gold_kept_in_our_kept += 1
        elif fn in o_quar_idx:
            rep.gold_kept_in_our_quarantined += 1
            if len(rep.gold_kept_in_our_quarantined_examples) < 10:
                rep.gold_kept_in_our_quarantined_examples.append(ge)
        else:
            rep.gold_kept_missing += 1
            if len(rep.gold_kept_missing_examples) < 10:
                rep.gold_kept_missing_examples.append(ge)

    for ge in g_quar:
        fn = ge.get("function")
        if not isinstance(fn, str):
            continue
        if fn in o_kept_idx:
            rep.gold_quarantined_in_our_kept += 1
        elif fn in o_quar_idx:
            rep.gold_quarantined_in_our_quarantined += 1
        else:
            rep.gold_quarantined_missing += 1

    g_fn_set = {e.get("function") for e in g_entries if isinstance(e.get("function"), str)}
    for oe in o_kept:
        if oe.get("function") not in g_fn_set:
            rep.our_kept_no_gold += 1
    for oe in o_quar:
        if oe.get("function") not in g_fn_set:
            rep.our_quarantined_no_gold += 1

    return rep
