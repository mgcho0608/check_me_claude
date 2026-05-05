"""Deterministic Step 1 substrate matcher.

For each row in the gold substrate, check whether a corresponding
row exists in our extracted substrate. Per-category match keys
are chosen to be robust to LLM-precision drift while still
detecting real differences:

  call_graph                   — (caller, callee, kind)
  trust_boundaries             — (function, kind, direction)
  callback_registrations       — (callback_function, kind)
  guards                       — (function, guard_call_first10words)
  evidence_anchors             — (file, line, kind)
  config_mode_command_triggers — (kind, name, file)
  data_control_flow            — (function, kind, summary_first6words)

The match key for ``guards`` and ``data_control_flow`` is loose
on purpose — those rows record free text that LLMs and even our
extractor sometimes phrase slightly differently across substrate
versions. Strict text equality would mark trivially-rephrased
rows as misses; the loose prefix-match captures intent without
over-strict false-fail behaviour.

Output for each category:
  - tp: rows in both gold and ours (gold count of matches)
  - fn: gold rows not present in ours (silently dropped)
  - fp: ours rows not present in gold (extras — informational,
        not a failure on its own; gold is curated, ours is
        extracted, extras can be legitimate)
  - recall: tp / (tp + fn) — the headline metric
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass
class CategoryReport:
    name: str
    gold_total: int
    ours_total: int
    tp: int = 0
    fn: int = 0
    fp: int = 0
    fn_examples: list[dict[str, Any]] = field(default_factory=list)
    fp_examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "gold_total": self.gold_total,
            "ours_total": self.ours_total,
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "recall": round(self.recall, 4),
            "fn_examples": self.fn_examples[:5],
            "fp_examples": self.fp_examples[:5],
        }


@dataclass
class SubstrateReport:
    project: str
    cve: str
    categories: dict[str, CategoryReport] = field(default_factory=dict)

    @property
    def overall_recall(self) -> float:
        tp = sum(c.tp for c in self.categories.values())
        fn = sum(c.fn for c in self.categories.values())
        return tp / (tp + fn) if (tp + fn) else 1.0

    def to_json(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "cve": self.cve,
            "overall_recall": round(self.overall_recall, 4),
            "by_category": {
                k: v.to_json() for k, v in self.categories.items()
            },
        }


# --------------------------------------------------------------------------- #
# Per-category match-key extractors
# --------------------------------------------------------------------------- #


def _first_n_words(s: Any, n: int) -> str:
    if not isinstance(s, str):
        return ""
    return " ".join(s.split()[:n]).lower()


_KEY_FNS: dict[str, Callable[[dict[str, Any]], tuple]] = {
    "call_graph": lambda r: (
        r.get("caller", ""), r.get("callee", ""), r.get("kind", ""),
    ),
    "trust_boundaries": lambda r: (
        r.get("function", ""), r.get("kind", ""), r.get("direction", ""),
    ),
    "callback_registrations": lambda r: (
        r.get("callback_function", ""), r.get("kind", ""),
    ),
    "guards": lambda r: (
        r.get("function", ""), _first_n_words(r.get("guard_call"), 10),
    ),
    "evidence_anchors": lambda r: (
        r.get("file", ""), r.get("line", -1), r.get("kind", ""),
    ),
    "config_mode_command_triggers": lambda r: (
        r.get("kind", ""), r.get("name", ""), r.get("file", ""),
    ),
    "data_control_flow": lambda r: (
        r.get("function", ""), r.get("kind", ""),
        _first_n_words(r.get("summary"), 6),
    ),
}


def _match_category(
    name: str,
    gold_rows: list[dict[str, Any]],
    ours_rows: list[dict[str, Any]],
) -> CategoryReport:
    key_fn = _KEY_FNS.get(name)
    if key_fn is None:
        # Unknown category — count rows but no per-row matching.
        return CategoryReport(
            name=name, gold_total=len(gold_rows), ours_total=len(ours_rows),
        )
    gold_keys: dict[tuple, dict[str, Any]] = {}
    for r in gold_rows:
        gold_keys.setdefault(key_fn(r), r)
    ours_keys: dict[tuple, dict[str, Any]] = {}
    for r in ours_rows:
        ours_keys.setdefault(key_fn(r), r)

    rep = CategoryReport(name=name, gold_total=len(gold_rows), ours_total=len(ours_rows))
    for k, gold_row in gold_keys.items():
        if k in ours_keys:
            rep.tp += 1
        else:
            rep.fn += 1
            if len(rep.fn_examples) < 10:
                rep.fn_examples.append(gold_row)
    for k, ours_row in ours_keys.items():
        if k not in gold_keys:
            rep.fp += 1
            if len(rep.fp_examples) < 10:
                rep.fp_examples.append(ours_row)
    return rep


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def match_substrate(
    gold: dict[str, Any],
    ours: dict[str, Any],
) -> SubstrateReport:
    """Match ``ours`` against ``gold`` substrate per-category."""
    project = gold.get("project") or ours.get("project") or "<unknown>"
    cve = gold.get("cve") or ours.get("cve") or "<unknown>"

    rep = SubstrateReport(project=project, cve=cve)
    g_cats = gold.get("categories", {}) or {}
    o_cats = ours.get("categories", {}) or {}
    all_cats = sorted(set(g_cats.keys()) | set(o_cats.keys()))
    for name in all_cats:
        rep.categories[name] = _match_category(
            name,
            list(g_cats.get(name, [])),
            list(o_cats.get(name, [])),
        )
    return rep
