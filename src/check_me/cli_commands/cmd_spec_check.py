"""check_me spec-check — scenario spec YAML 유효성 검사."""

from __future__ import annotations

from pathlib import Path

import click
import yaml

from check_me.profiles.registry import ProfileRegistry

_REQUIRED_SPEC_FIELDS = ["name", "description", "candidate_families"]

_KNOWN_FAMILIES: set[str] = {
    "UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK",
    "ACTION_BEFORE_REQUIRED_CHECK",
    "RESULT_NOT_ENFORCED",
    "VERSION_POLICY_WEAK_OR_INCONSISTENT",
    "ROLLBACK_PROTECTION_MISSING_OR_WEAK",
    "PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE",
    "STATE_PERSISTENCE_REPLAY_RISK",
    "VERIFY_BEFORE_EXECUTE_MISSING",
    "CHAIN_OF_TRUST_GAP",
    "SELF_TEST_BEFORE_CRYPTO_MISSING",
    "NARROW_COMPARE_IN_SECRET_CONTEXT",
    "COUNTERMEASURE_SETUP_MISSING",
    "STALE_STATE_AFTER_FAILURE",
    "FAILURE_CLEANUP_MISSING",
    "RECOVERY_PATH_STATE_INTEGRITY",
}


@click.command()
@click.option("--scenario-spec", required=True, type=click.Path(exists=True),
              help="검사할 scenario spec YAML 경로")
def spec_check(scenario_spec: str) -> None:
    """scenario spec YAML의 스키마와 내용을 검증한다."""
    spec_path = Path(scenario_spec)
    issues: list[str] = []

    # 1. YAML 파싱
    try:
        with spec_path.open(encoding="utf-8") as f:
            spec = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        click.echo(f"[spec-check] FAILED — YAML parse error: {e}")
        raise SystemExit(1)

    if not isinstance(spec, dict):
        click.echo("[spec-check] FAILED — spec must be a YAML mapping")
        raise SystemExit(1)

    # 2. 필수 필드 존재 확인
    for field in _REQUIRED_SPEC_FIELDS:
        if field not in spec:
            issues.append(f"missing required field: '{field}'")

    # 3. candidate_families 검사
    families = spec.get("candidate_families", [])
    if not isinstance(families, list):
        issues.append("'candidate_families' must be a list")
    else:
        if len(families) == 0:
            issues.append("'candidate_families' is empty")
        for fam in families:
            if fam not in _KNOWN_FAMILIES:
                issues.append(f"unknown candidate_family: '{fam}'")
            if families.count(fam) > 1:
                issues.append(f"duplicate candidate_family: '{fam}'")

    # 4. 선택 필드 타입 확인
    if "profile_ref" in spec:
        registry = ProfileRegistry()
        pid = spec["profile_ref"]
        if registry.get(pid) is None:
            issues.append(f"profile_ref '{pid}' not found — run `check_me list-profiles`")

    if issues:
        click.echo(f"[spec-check] FAILED — {len(issues)} issue(s):")
        for issue in issues:
            click.echo(f"  - {issue}")
        raise SystemExit(1)

    click.echo(f"[spec-check] OK — {spec_path.name}")
    click.echo(f"  name: {spec.get('name')}")
    click.echo(f"  families: {families}")
