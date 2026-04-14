"""Profile registry 테스트."""

from __future__ import annotations

import pytest

from check_me.profiles.registry import ProfileRegistry


def test_all_profiles_have_required_metadata():
    registry = ProfileRegistry()
    for p in registry.all():
        assert p.profile_id, "profile_id is empty"
        assert p.maturity in {"stable", "experimental"}, f"invalid maturity: {p.maturity}"
        assert p.description, "description is empty"
        assert p.intended_domain, "intended_domain is empty"
        assert len(p.enabled_candidate_families) > 0, "no candidate families"


def test_stable_profiles_exist():
    registry = ProfileRegistry()
    stable = [p for p in registry.all() if p.maturity == "stable"]
    assert len(stable) >= 2


def test_experimental_profiles_exist():
    registry = ProfileRegistry()
    exp = [p for p in registry.all() if p.maturity == "experimental"]
    assert len(exp) >= 3


def test_get_known_profile():
    registry = ProfileRegistry()
    p = registry.get("secure_update_install_integrity")
    assert p is not None
    assert p.maturity == "stable"


def test_get_unknown_profile_returns_none():
    registry = ProfileRegistry()
    assert registry.get("nonexistent") is None


def test_profile_ids_unique():
    registry = ProfileRegistry()
    ids = registry.ids()
    assert len(ids) == len(set(ids)), "duplicate profile IDs"


def test_no_duplicate_candidate_families_within_profile():
    registry = ProfileRegistry()
    for p in registry.all():
        families = p.enabled_candidate_families
        assert len(families) == len(set(families)), \
            f"duplicate families in profile {p.profile_id}"
