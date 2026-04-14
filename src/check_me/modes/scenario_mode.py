"""Scenario Mode — domain profile 기반 보안 명세 위반 후보 생성 (개선판).

개선 사항:
- primitives(result-use links, enforcement links) 기반 guard 존재 여부 정밀화
- RESULT_NOT_ENFORCED: guard가 있어도 result-use link가 없으면 후보
- state_lifecycle 기반 stale state 힌트
- confidence 보정: enforcement link 있으면 낮아짐, 없으면 유지
"""

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
        symbols = self._load("symbols.json")
        call_graph = self._load("call_graph.json")
        primitives_list = self._load("primitives.json")

        primitives_idx = {p["function_id"]: p for p in primitives_list} \
            if isinstance(primitives_list, list) else {}

        functions = symbols.get("functions", []) if isinstance(symbols, dict) else []

        candidates = self._generate_candidates(
            functions, call_graph, primitives_idx, profile_obj, spec
        )
        guard_evidence = self._collect_guard_evidence(functions, call_graph, primitives_idx)

        self._write("scenario_candidates.json", candidates)
        self._write("guard_evidence.json", guard_evidence)

        if profile_obj:
            self._write("profile_summary.json", {
                "profile_id": profile_obj.profile_id,
                "maturity": profile_obj.maturity,
                "candidate_count": len(candidates),
                "enabled_families": profile_obj.enabled_candidate_families,
            })

        return ModeResult(candidate_count=len(candidates))

    # ------------------------------------------------------------------
    # Profile / spec loading
    # ------------------------------------------------------------------

    def _resolve_profile(self):
        if self.profile_id is None:
            return None
        registry = ProfileRegistry()
        profile = registry.get(self.profile_id)
        if profile is None:
            raise ValueError(
                f"Unknown profile: {self.profile_id}. "
                "Run `check_me list-profiles` to see available profiles."
            )
        return profile

    def _load_spec(self) -> dict:
        if self.scenario_spec is None:
            return {}
        with self.scenario_spec.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # ------------------------------------------------------------------
    # Candidate generation
    # ------------------------------------------------------------------

    def _generate_candidates(
        self,
        functions: list[dict],
        call_graph: dict,
        primitives_idx: dict,
        profile,
        spec: dict,
    ) -> list[dict]:
        families = (
            profile.enabled_candidate_families if profile
            else spec.get("candidate_families", [])
        )

        candidates: list[dict] = []
        for family in families:
            candidates.extend(
                self._check_family(family, functions, call_graph, primitives_idx)
            )

        # deterministic ordering
        return sorted(candidates, key=lambda c: (c["family"], c["candidate_id"]))

    def _check_family(
        self,
        family: str,
        functions: list[dict],
        call_graph: dict,
        primitives_idx: dict,
    ) -> list[dict]:
        family_patterns: dict[str, dict] = {
            "UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK": {
                "action_keywords": ["install", "write", "flash", "update", "activate"],
                "check_keywords": ["verify", "authenticate", "validate", "check_signature",
                                   "check_integrity"],
            },
            "ACTION_BEFORE_REQUIRED_CHECK": {
                "action_keywords": ["execute", "run", "apply", "commit", "deploy"],
                "check_keywords": ["verify", "check", "validate", "authorize"],
            },
            "RESULT_NOT_ENFORCED": {
                "action_keywords": ["write", "send", "execute", "delete", "install",
                                    "flash", "apply", "activate"],
                "check_keywords": ["check", "verify", "validate"],
            },
            "VERSION_POLICY_WEAK_OR_INCONSISTENT": {
                "action_keywords": ["version", "rollback", "downgrade", "flash"],
                "check_keywords": ["compare_version", "check_version", "enforce_version",
                                   "get_current_version"],
            },
            "ROLLBACK_PROTECTION_MISSING_OR_WEAK": {
                "action_keywords": ["rollback", "restore", "revert", "flash"],
                "check_keywords": ["anti_rollback", "rollback_check", "version_fence"],
            },
            "PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE": {
                "action_keywords": ["admin", "privileged", "root", "sudo", "elevate",
                                    "grant", "delete"],
                "check_keywords": ["authenticated", "authorized", "verified", "session_valid",
                                   "check_authenticated", "verify_session"],
            },
            "STATE_PERSISTENCE_REPLAY_RISK": {
                "action_keywords": ["persist", "store", "cache", "save_session", "restore"],
                "check_keywords": ["invalidate", "revoke", "expire", "nonce"],
            },
            # Experimental profile families
            "VERIFY_BEFORE_EXECUTE_MISSING": {
                "action_keywords": ["execute", "run", "boot", "launch"],
                "check_keywords": ["verify", "check_signature", "validate"],
            },
            "CHAIN_OF_TRUST_GAP": {
                "action_keywords": ["boot", "load", "execute", "jump"],
                "check_keywords": ["verify_chain", "check_chain", "validate_boot"],
            },
            "SELF_TEST_BEFORE_CRYPTO_MISSING": {
                "action_keywords": ["encrypt", "decrypt", "sign", "verify_mac"],
                "check_keywords": ["self_test", "crypto_test", "fips_test"],
            },
            "NARROW_COMPARE_IN_SECRET_CONTEXT": {
                "action_keywords": ["compare", "memcmp", "strcmp"],
                "check_keywords": ["constant_time_compare", "secure_compare"],
            },
            "COUNTERMEASURE_SETUP_MISSING": {
                "action_keywords": ["encrypt", "decrypt", "sign"],
                "check_keywords": ["setup_countermeasure", "init_protection"],
            },
            "STALE_STATE_AFTER_FAILURE": {
                "action_keywords": ["apply", "activate", "install"],
                "check_keywords": ["clear_state", "reset_state", "invalidate"],
            },
            "FAILURE_CLEANUP_MISSING": {
                "action_keywords": ["recover", "restart", "reset"],
                "check_keywords": ["cleanup", "clear", "free"],
            },
            "RECOVERY_PATH_STATE_INTEGRITY": {
                "action_keywords": ["recover", "restore", "resume"],
                "check_keywords": ["validate_state", "check_state", "verify_state"],
            },
        }

        pattern = family_patterns.get(family)
        if pattern is None:
            return []

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

        candidates: list[dict] = []
        for af in action_funcs:
            callees = set(call_graph.get(af["id"], []))
            guard_callees = callees & check_names

            # primitives로 guard 정밀 분석
            prim = primitives_idx.get(af["id"], {})
            enforcement_links = prim.get("enforcement_links", [])
            result_use_links = prim.get("result_use_links", [])
            state_lifecycle = prim.get("state_lifecycle", [])

            # guard가 호출되더라도 result가 쓰이지 않으면 RESULT_NOT_ENFORCED
            guard_result_used = bool(result_use_links) and bool(enforcement_links)
            guard_present = bool(guard_callees)

            state, confidence = _assess_state(
                family=family,
                guard_present=guard_present,
                guard_result_used=guard_result_used,
                enforcement_links=enforcement_links,
                state_lifecycle=state_lifecycle,
            )

            candidates.append({
                "candidate_id": f"scenario_{family}_{af['name']}",
                "family": family,
                "type": "structural_concern",
                "state": state,
                "evidence": {
                    "action_function": {
                        "id": af["id"],
                        "name": af["name"],
                        "file": af["file"],
                        "line": af["line"],
                    },
                    "guard_present": guard_present,
                    "guard_functions_found": sorted(guard_callees),
                    "guard_result_used": guard_result_used,
                    "enforcement_link_count": len(enforcement_links),
                    "result_use_link_count": len(result_use_links),
                    "state_lifecycle_hints": [
                        {"flag": s["flag_name"], "value": s["assigned_value"], "line": s["line"]}
                        for s in state_lifecycle
                    ],
                },
                "confidence": confidence,
                "claim": "structurally identified candidate",
                "profile_id": self.profile_id,
                "heuristic": True,
            })

        return candidates

    # ------------------------------------------------------------------
    # Guard evidence
    # ------------------------------------------------------------------

    def _collect_guard_evidence(
        self,
        functions: list[dict],
        call_graph: dict,
        primitives_idx: dict,
    ) -> list[dict]:
        guard_keywords = ["verify", "check", "validate", "authenticate", "authorize"]
        evidence: list[dict] = []

        for f in functions:
            if not any(kw in f["name"].lower() for kw in guard_keywords):
                continue

            callees = call_graph.get(f["id"], [])
            prim = primitives_idx.get(f["id"], {})

            evidence.append({
                "function_id": f["id"],
                "name": f["name"],
                "file": f["file"],
                "line": f["line"],
                "direct_callees": callees,
                "result_use_links": prim.get("result_use_links", []),
                "enforcement_links": prim.get("enforcement_links", []),
                "state_lifecycle": prim.get("state_lifecycle", []),
                "decision_input_hints": prim.get("decision_input_hints", []),
            })

        return sorted(evidence, key=lambda e: (e["file"], e["line"]))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load(self, name: str) -> dict | list:
        path = self.output_dir / name
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _assess_state(
    family: str,
    guard_present: bool,
    guard_result_used: bool,
    enforcement_links: list[dict],
    state_lifecycle: list[dict],
) -> tuple[str, str]:
    """
    structural evidence를 바탕으로 candidate state와 confidence를 결정한다.
    confidence는 low ~ moderate만 허용 (PLAN.md §12.2).
    """
    # guard도 없고 result-use도 없으면 가장 강한 structural concern
    if not guard_present:
        # stale state 힌트가 있으면 moderate
        if state_lifecycle:
            return "ACTIVE", "moderate"
        return "ACTIVE", "low"

    # guard는 있지만 결과가 쓰이지 않는 경우
    if guard_present and not guard_result_used:
        if family == "RESULT_NOT_ENFORCED":
            return "ACTIVE", "moderate"
        return "ACTIVE", "low"

    # guard가 있고 enforcement link도 있으면 위험도 낮음
    if enforcement_links:
        return "SANITIZER_AFFECTED", "low"

    # guard는 있는데 enforcement link가 없는 경우
    return "ACTIVE", "low"
