"""stats 아티팩트 읽기 및 요약."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


class StatsReader:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def summarize(self) -> str:
        """CLI 출력용 한 줄 요약."""
        data = self._read_stats()
        if data is None:
            return "stats.json not found — run `check_me index` first"
        parts = [f"{k}={v}" for k, v in data.items()]
        return ", ".join(parts)

    def full_report(self) -> dict:
        """
        전체 분석 결과 report.
        stats.json + 모든 candidate artifact를 읽어 통합 요약을 반환한다.
        """
        stats = self._read_stats() or {}
        report: dict = {
            "index": stats,
            "code_candidates": self._candidate_summary("code_candidates.json"),
            "scenario_candidates": self._candidate_summary("scenario_candidates.json"),
            "primitives_summary": self._primitives_summary(),
            "interpretations": self._interpretation_summary(),
            "validation": self._validation_status(),
        }
        return report

    # ------------------------------------------------------------------

    def _read_stats(self) -> dict | None:
        path = self.output_dir / "stats.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _candidate_summary(self, filename: str) -> dict:
        path = self.output_dir / filename
        if not path.exists():
            return {"available": False}

        candidates = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(candidates, list):
            return {"available": False}

        state_counts = Counter(c.get("state") for c in candidates)
        confidence_counts = Counter(c.get("confidence") for c in candidates)
        family_counts = Counter(c.get("family") or c.get("rule_id") for c in candidates)

        return {
            "available": True,
            "total": len(candidates),
            "by_state": dict(sorted(state_counts.items())),
            "by_confidence": dict(sorted(confidence_counts.items())),
            "by_family": dict(sorted(family_counts.items())),
        }

    def _primitives_summary(self) -> dict:
        path = self.output_dir / "primitives.json"
        if not path.exists():
            return {"available": False}

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return {"available": False}

        total_rul = sum(len(p.get("result_use_links", [])) for p in data)
        total_enf = sum(len(p.get("enforcement_links", [])) for p in data)
        total_slc = sum(len(p.get("state_lifecycle", [])) for p in data)
        total_dih = sum(len(p.get("decision_input_hints", [])) for p in data)
        funcs_with_rul = sum(1 for p in data if p.get("result_use_links"))
        funcs_with_enf = sum(1 for p in data if p.get("enforcement_links"))

        return {
            "available": True,
            "function_count": len(data),
            "result_use_links": total_rul,
            "enforcement_links": total_enf,
            "state_lifecycle_entries": total_slc,
            "decision_input_hints": total_dih,
            "functions_with_result_use": funcs_with_rul,
            "functions_with_enforcement": funcs_with_enf,
        }

    def _interpretation_summary(self) -> dict:
        path = self.output_dir / "interpretations.json"
        if not path.exists():
            return {"available": False}

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return {"available": False}

        llm_used = sum(1 for i in data if i.get("llm_used"))
        return {
            "available": True,
            "total": len(data),
            "llm_used": llm_used,
            "placeholder": len(data) - llm_used,
        }

    def _validation_status(self) -> dict:
        """validate 결과를 stats 안에 포함한다."""
        from check_me.core.validator import Validator
        ok, issues = Validator(output_dir=self.output_dir).run()
        return {"ok": ok, "issue_count": len(issues), "issues": issues}
