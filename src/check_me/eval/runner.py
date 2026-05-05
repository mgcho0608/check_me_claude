"""End-to-end evaluation runner — gold vs pipeline output across
all 4 steps for a single dataset.

Loads gold from ``datasets/<key>/gold/*.json`` and pipeline output
from ``out/<key>/*.json``. Runs the four matchers and writes a
single ``eval_report.json`` per dataset summarising per-step
metrics and overall pass / fail per PLAN exit criteria
(§5 Stage 3).

Step 1 + Step 2 are deterministic — no LLM calls. Step 3 +
Step 4 use the LLM judge once per (gold, top-K-candidate) pair.
The runner exposes ``judge_chat_fn`` so unit tests can stub the
LLM and verify matcher behaviour without a live call; production
runs leave it at the default ``chat`` from ``check_me.llm.client``.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat, make_client
from ..llm.config import Config, StepKind, load_config
from . import step1_match, step2_match, step3_match, step4_match

logger = logging.getLogger(__name__)


@dataclass
class EvalReport:
    project: str
    cve: str
    elapsed_sec: float = 0.0
    step1: dict[str, Any] = field(default_factory=dict)
    step2: dict[str, Any] = field(default_factory=dict)
    step3: dict[str, Any] = field(default_factory=dict)
    step4: dict[str, Any] = field(default_factory=dict)
    exit_criteria: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": "v1",
            "project": self.project,
            "cve": self.cve,
            "elapsed_sec": round(self.elapsed_sec, 2),
            "step1_substrate": self.step1,
            "step2_entrypoints": self.step2,
            "step3_evidence_irs": self.step3,
            "step4_attack_scenarios": self.step4,
            "exit_criteria": self.exit_criteria,
        }


def _load(p: Path) -> dict[str, Any]:
    return json.loads(p.read_text())


def run(
    *,
    gold_dir: Path,
    out_dir: Path,
    eval_report_path: Path | None = None,
    judge_config: Config | None = None,
    judge_client: Any | None = None,
    skip_step3: bool = False,
    skip_step4: bool = False,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> EvalReport:
    """Run all four matchers for one dataset.

    ``gold_dir`` should contain ``substrate.json``,
    ``entrypoints.json``, ``evidence_irs.json``,
    ``attack_scenarios.json``. ``out_dir`` should contain the
    pipeline's outputs at the same filenames.

    ``skip_step3`` / ``skip_step4`` skip the LLM-judge passes
    (useful for fast Step 1+2-only sanity checks).

    Tests pass a stub ``chat_fn``; production leaves it at the
    default. ``judge_config`` is loaded from env if not supplied.
    """
    start = time.monotonic()
    gold_dir = Path(gold_dir)
    out_dir = Path(out_dir)

    g_sub = _load(gold_dir / "substrate.json")
    o_sub = _load(out_dir / "substrate.json")
    g_ep = _load(gold_dir / "entrypoints.json")
    o_ep = _load(out_dir / "entrypoints.json")

    project = g_sub.get("project") or g_ep.get("project") or "<unknown>"
    cve = g_sub.get("cve") or g_ep.get("cve") or "<unknown>"
    rep = EvalReport(project=project, cve=cve)

    logger.info("eval: %s %s — Step 1 substrate", project, cve)
    s1 = step1_match.match_substrate(g_sub, o_sub)
    rep.step1 = s1.to_json()

    logger.info("eval: %s %s — Step 2 entrypoints", project, cve)
    s2 = step2_match.match_entrypoints(g_ep, o_ep)
    rep.step2 = s2.to_json()

    if not (skip_step3 and skip_step4):
        if judge_config is None:
            # Reuse Step 2 verifier config posture: low temperature,
            # quiet reasoning. The judge is a small classifier.
            judge_config = load_config(step=StepKind.STEP2_VERIFIER)
        if judge_client is None:
            judge_client = make_client(judge_config)

    if not skip_step3:
        ir_path = out_dir / "evidence_irs.json"
        gir_path = gold_dir / "evidence_irs.json"
        if ir_path.is_file() and gir_path.is_file():
            logger.info("eval: %s %s — Step 3 IRs (LLM judge)", project, cve)
            s3 = step3_match.match_irs(
                _load(gir_path), _load(ir_path),
                judge_client=judge_client, judge_config=judge_config,
                chat_fn=chat_fn,
            )
            rep.step3 = s3.to_json()
        else:
            rep.step3 = {"skipped": "evidence_irs.json missing"}

    if not skip_step4:
        as_path = out_dir / "attack_scenarios.json"
        gas_path = gold_dir / "attack_scenarios.json"
        if as_path.is_file() and gas_path.is_file():
            logger.info("eval: %s %s — Step 4 scenarios (LLM judge)", project, cve)
            s4 = step4_match.match_scenarios(
                _load(gas_path), _load(as_path),
                judge_client=judge_client, judge_config=judge_config,
                chat_fn=chat_fn,
            )
            rep.step4 = s4.to_json()
        else:
            rep.step4 = {"skipped": "attack_scenarios.json missing"}

    # Exit criteria evaluation per PLAN §5 Stage 3.
    rep.exit_criteria = _evaluate_exit_criteria(rep)
    rep.elapsed_sec = time.monotonic() - start

    if eval_report_path is not None:
        eval_report_path = Path(eval_report_path)
        eval_report_path.parent.mkdir(parents=True, exist_ok=True)
        eval_report_path.write_text(json.dumps(rep.to_json(), indent=2) + "\n")
    return rep


def _evaluate_exit_criteria(rep: EvalReport) -> dict[str, Any]:
    """Map per-step metrics to PLAN exit criteria.

    Two criteria are honoured here (cost analysis is intentionally
    out of scope for this evaluator — see PLAN Appendix A
    "deferred to operator preference"):

      EC-1: Step 1 substrate recall ≥ 0.7
      EC-2: Step 2 gold-kept-anywhere recall ≥ 0.8
      EC-3: Step 3 IR equivalent_recall ≥ 0.6
      EC-4: Step 4 scenario equivalent_recall ≥ 0.6

    Thresholds are starting points; tune as more datasets are
    added. The thresholds themselves are not project-specific.
    """
    out: dict[str, Any] = {}

    s1_recall = rep.step1.get("overall_recall")
    out["EC-1_step1_substrate_recall>=0.7"] = (
        bool(isinstance(s1_recall, (int, float)) and s1_recall >= 0.7),
        s1_recall,
    )

    s2_anywhere = rep.step2.get("gold_kept_recall_anywhere")
    out["EC-2_step2_gold_kept_anywhere_recall>=0.8"] = (
        bool(isinstance(s2_anywhere, (int, float)) and s2_anywhere >= 0.8),
        s2_anywhere,
    )

    s3_recall = rep.step3.get("equivalent_recall") if isinstance(rep.step3, dict) else None
    out["EC-3_step3_equivalent_recall>=0.6"] = (
        bool(isinstance(s3_recall, (int, float)) and s3_recall >= 0.6),
        s3_recall,
    )

    s4_recall = rep.step4.get("equivalent_recall") if isinstance(rep.step4, dict) else None
    out["EC-4_step4_equivalent_recall>=0.6"] = (
        bool(isinstance(s4_recall, (int, float)) and s4_recall >= 0.6),
        s4_recall,
    )

    out["all_pass"] = all(v[0] for v in out.values() if isinstance(v, tuple))
    return out
