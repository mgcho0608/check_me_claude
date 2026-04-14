"""Scenario Mode — domain profile 기반 보안 명세 위반 후보 생성."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from check_me.config import LLMConfig
from check_me.profiles.registry import ProfileRegistry


@dataclass
class ModeResult:
    candidate_count: int


class ScenarioMode:
    def __init__(
        self,
        dir_path: Path,
        compile_commands: Path | None,
        output_dir: Path,
        profile: str | None,
        scenario_spec: Path | None,
        llm_config: LLMConfig,
    ) -> None:
        self.dir_path = dir_path
        self.compile_commands = compile_commands
        self.output_dir = output_dir
        self.profile_id = profile
        self.scenario_spec = scenario_spec
        self.llm_config = llm_config

    def run(self) -> ModeResult:
        profile_obj = self._resolve_profile()
        spec = self._load_spec()
        symbols = self._load_artifact("symbols.json")
        call_graph = self._load_artifact("call_graph.json")

        candidates = self._generate_candidates(symbols, call_graph, profile_obj, spec)
        guard_evidence = self._collect_guard_evidence(symbols, call_graph)

        self._write_artifact("scenario_candidates.json", candidates)
        self._write_artifact("guard_evidence.json", guard_evidence)

        if profile_obj:
            self._write_artifact(
                "profile_summary.json",
                {
                    "profile_id": profile_obj.profile_id,
                    "maturity": profile_obj.maturity,
                    "candidate_count": len(candidates),
                    "enabled_families": profile_obj.enabled_candidate_families,
                },
            )

        return ModeResult(candidate_count=len(candidates))

    # ------------------------------------------------------------------

    def _resolve_profile(self):
        if self.profile_id is None:
            return None
        registry = ProfileRegistry()
        profile = registry.get(self.profile_id)
        if profile is None:
            raise ValueError(f"Unknown profile: {self.profile_id}. Run `check_me list-profiles` to see available profiles.")
        return profile

    def _load_spec(self) -> dict:
        if self.scenario_spec is None:
            return {}
        with self.scenario_spec.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _load_artifact(self, name: str) -> dict | list:
        path = self.output_dir / name
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _generate_candidates(
        self,
        symbols: dict,
        call_graph: dict,
        profile,
        spec: dict,
    ) -> list[dict]:
        """profile의 candidate family에 따라 구조적 후보를 생성한다."""
        functions = symbols.get("functions", []) if isinstance(symbols, dict) else []
        families = profile.enabled_candidate_families if profile else spec.get("candidate_families", [])

        candidates: list[dict] = []
        for family in families:
            family_candidates = self._check_family(family, functions, call_graph)
            candidates.extend(family_candidates)

        # deterministic ordering
        candidates.sort(key=lambda c: (c["family"], c["candidate_id"]))
        return candidates

    def _check_family(
        self,
        family: str,
        functions: list[dict],
        call_graph: dict,
    ) -> list[dict]:
        """각 candidate family에 대한 구조적 패턴을 검사한다."""
        # 각 family별 패턴 키워드 매핑
        family_patterns: dict[str, dict] = {
            "UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK": {
                "action_keywords": ["install", "write", "flash", "update", "activate"],
                "check_keywords": ["verify", "authenticate", "validate", "check_signature"],
            },
            "ACTION_BEFORE_REQUIRED_CHECK": {
                "action_keywords": ["execute", "run", "apply", "commit", "deploy"],
                "check_keywords": ["verify", "check", "validate", "authorize"],
            },
            "RESULT_NOT_ENFORCED": {
                "action_keywords": ["write", "send", "execute", "delete"],
                "check_keywords": ["check", "verify", "validate"],
            },
            "VERSION_POLICY_WEAK_OR_INCONSISTENT": {
                "action_keywords": ["version", "rollback", "downgrade"],
                "check_keywords": ["compare_version", "check_version", "enforce_version"],
            },
            "ROLLBACK_PROTECTION_MISSING_OR_WEAK": {
                "action_keywords": ["rollback", "restore", "revert"],
                "check_keywords": ["anti_rollback", "rollback_check", "version_fence"],
            },
            "PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE": {
                "action_keywords": ["admin", "privileged", "root", "sudo", "elevate"],
                "check_keywords": ["authenticated", "authorized", "verified", "session_valid"],
            },
            "STATE_PERSISTENCE_REPLAY_RISK": {
                "action_keywords": ["persist", "store", "cache", "save_session"],
                "check_keywords": ["invalidate", "revoke", "expire", "nonce"],
            },
        }

        pattern = family_patterns.get(family)
        if pattern is None:
            return []

        candidates: list[dict] = []
        action_kw = pattern["action_keywords"]
        check_kw = pattern["check_keywords"]

        action_funcs = [
            f for f in functions
            if any(kw in f["name"].lower() for kw in action_kw)
        ]
        check_funcs = [
            f for f in functions
            if any(kw in f["name"].lower() for kw in check_kw)
        ]
        check_names = {f["name"] for f in check_funcs}

        for af in action_funcs:
            callees = set(call_graph.get(af["id"], []))
            guard_present = bool(callees & check_names)

            candidates.append(
                {
                    "candidate_id": f"scenario_{family}_{af['name']}",
                    "family": family,
                    "type": "structural_concern",
                    "state": "ACTIVE" if not guard_present else "SANITIZER_AFFECTED",
                    "evidence": {
                        "action_function": {"id": af["id"], "file": af["file"], "line": af["line"]},
                        "guard_present": guard_present,
                        "guard_functions_found": list(callees & check_names),
                    },
                    "confidence": "low",
                    "claim": "structurally identified candidate",
                    "profile_id": self.profile_id,
                }
            )

        return candidates

    def _collect_guard_evidence(self, symbols: dict, call_graph: dict) -> list[dict]:
        functions = symbols.get("functions", []) if isinstance(symbols, dict) else []
        evidence: list[dict] = []

        guard_keywords = ["verify", "check", "validate", "authenticate", "authorize"]
        for f in functions:
            if any(kw in f["name"].lower() for kw in guard_keywords):
                callees = call_graph.get(f["id"], [])
                evidence.append(
                    {
                        "function_id": f["id"],
                        "name": f["name"],
                        "file": f["file"],
                        "line": f["line"],
                        "direct_callees": callees,
                        "result_use_hint": None,
                        "enforcement_link": None,
                    }
                )

        return sorted(evidence, key=lambda e: (e["file"], e["line"]))

    def _write_artifact(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
