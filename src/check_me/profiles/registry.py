"""도메인 프로필 레지스트리."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Profile:
    profile_id: str
    maturity: str  # stable | experimental
    description: str
    intended_domain: str
    enabled_candidate_families: list[str] = field(default_factory=list)
    primary_artifacts: list[str] = field(default_factory=list)


_BUILTIN_PROFILES: list[Profile] = [
    Profile(
        profile_id="secure_update_install_integrity",
        maturity="stable",
        description="업데이트/설치 경로의 무결성 검증 누락 후보 탐지",
        intended_domain="firmware/software update pipelines",
        enabled_candidate_families=[
            "UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK",
            "ACTION_BEFORE_REQUIRED_CHECK",
            "RESULT_NOT_ENFORCED",
            "VERSION_POLICY_WEAK_OR_INCONSISTENT",
            "ROLLBACK_PROTECTION_MISSING_OR_WEAK",
        ],
        primary_artifacts=["scenario_candidates.json", "guard_evidence.json"],
    ),
    Profile(
        profile_id="auth_session_replay_state",
        maturity="stable",
        description="인증/세션 상태 없이 privileged action 접근 후보 탐지",
        intended_domain="authentication and session management",
        enabled_candidate_families=[
            "PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE",
            "STATE_PERSISTENCE_REPLAY_RISK",
            "RESULT_NOT_ENFORCED",
        ],
        primary_artifacts=["scenario_candidates.json", "guard_evidence.json"],
    ),
    Profile(
        profile_id="secure_boot_chain",
        maturity="experimental",
        description="부트 체인 verify-before-execute 누락 후보 탐지",
        intended_domain="secure boot / bootloader",
        enabled_candidate_families=[
            "VERIFY_BEFORE_EXECUTE_MISSING",
            "CHAIN_OF_TRUST_GAP",
        ],
        primary_artifacts=["scenario_candidates.json"],
    ),
    Profile(
        profile_id="crypto_operational_assurance",
        maturity="experimental",
        description="암호 연산 전 self-test 누락 및 narrow compare 후보 탐지",
        intended_domain="cryptographic operations",
        enabled_candidate_families=[
            "SELF_TEST_BEFORE_CRYPTO_MISSING",
            "NARROW_COMPARE_IN_SECRET_CONTEXT",
            "COUNTERMEASURE_SETUP_MISSING",
        ],
        primary_artifacts=["scenario_candidates.json"],
    ),
    Profile(
        profile_id="error_recovery_state_integrity",
        maturity="experimental",
        description="오류/복구 후 stale state 재사용 후보 탐지",
        intended_domain="error handling and recovery paths",
        enabled_candidate_families=[
            "STALE_STATE_AFTER_FAILURE",
            "FAILURE_CLEANUP_MISSING",
            "RECOVERY_PATH_STATE_INTEGRITY",
        ],
        primary_artifacts=["scenario_candidates.json"],
    ),
]


class ProfileRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, Profile] = {p.profile_id: p for p in _BUILTIN_PROFILES}

    def all(self) -> list[Profile]:
        return list(self._profiles.values())

    def get(self, profile_id: str) -> Profile | None:
        return self._profiles.get(profile_id)

    def ids(self) -> list[str]:
        return list(self._profiles.keys())
