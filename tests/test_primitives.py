"""Primitives extractor 테스트 — result-use links, enforcement links, state lifecycle."""

from __future__ import annotations

import pytest

from check_me.core.primitives import PrimitivesExtractor


@pytest.fixture
def extractor():
    return PrimitivesExtractor()


# ──────────────────────────────────────────────────────────────
# Result-use links
# ──────────────────────────────────────────────────────────────

def test_result_use_if_guard(extractor):
    body = """\
{
    if (verify_signature(&hdr)) {
        install_firmware(buf, size);
    }
}"""
    prims = extractor.extract("file.c::func", body)
    names = [r.guard_name for r in prims.result_use_links]
    assert "verify_signature" in names


def test_result_use_negated_guard(extractor):
    body = """\
{
    if (!check_authenticated(&s)) {
        return -1;
    }
    admin_action(cmd);
}"""
    prims = extractor.extract("file.c::func", body)
    names = [r.guard_name for r in prims.result_use_links]
    assert "check_authenticated" in names


def test_result_use_assign_pattern(extractor):
    body = """\
{
    int ret = validate_hash(buf, size);
    if (ret != 0) return -1;
}"""
    prims = extractor.extract("file.c::func", body)
    names = [r.guard_name for r in prims.result_use_links]
    assert "validate_hash" in names


def test_no_result_use_when_guard_not_in_condition(extractor):
    """guard가 호출되지만 결과가 조건에 쓰이지 않는 경우."""
    body = """\
{
    verify_signature(&hdr);   /* call but result not used */
    install_firmware(buf, len);
}"""
    prims = extractor.extract("file.c::func", body)
    # if_ 패턴은 없어야 함 (assign 패턴도 없어야 함)
    if_links = [r for r in prims.result_use_links if r.pattern == "if_guard"]
    assert len(if_links) == 0


# ──────────────────────────────────────────────────────────────
# Enforcement links
# ──────────────────────────────────────────────────────────────

def test_enforcement_link_guard_before_action(extractor):
    body = """\
{
    if (!verify_signature(&hdr)) {
        return -1;
    }
    install_firmware(buf, len);
}"""
    prims = extractor.extract("file.c::func", body)
    assert len(prims.enforcement_links) > 0
    link = prims.enforcement_links[0]
    assert link.guard_name == "verify_signature"
    assert link.guard_result_used is True
    assert link.guard_line < link.action_line


def test_no_enforcement_link_without_result_use(extractor):
    """result-use 없으면 enforcement link도 없다."""
    body = """\
{
    verify_signature(&hdr);   /* not in condition */
    install_firmware(buf, len);
}"""
    prims = extractor.extract("file.c::func", body)
    assert len(prims.enforcement_links) == 0


# ──────────────────────────────────────────────────────────────
# State lifecycle
# ──────────────────────────────────────────────────────────────

def test_state_lifecycle_verified_true(extractor):
    body = """\
{
    hdr->verified = true;
    trusted_header = *hdr;
}"""
    prims = extractor.extract("file.c::func", body)
    flags = [(s.flag_name, s.assigned_value) for s in prims.state_lifecycle]
    assert ("verified", "true") in flags


def test_state_lifecycle_authenticated_false(extractor):
    body = """\
{
    s->authenticated = false;
    s->token = 0;
}"""
    prims = extractor.extract("file.c::func", body)
    flags = [(s.flag_name, s.assigned_value) for s in prims.state_lifecycle]
    assert ("authenticated", "false") in flags


def test_state_lifecycle_empty_when_no_flags(extractor):
    body = """\
{
    memcpy(dst, src, size);
    return 0;
}"""
    prims = extractor.extract("file.c::func", body)
    assert len(prims.state_lifecycle) == 0


# ──────────────────────────────────────────────────────────────
# Decision input hints
# ──────────────────────────────────────────────────────────────

def test_decision_input_external_hint(extractor):
    body = """\
{
    if (!verify_signature(buf)) return -1;
}"""
    prims = extractor.extract("file.c::func", body)
    hints = {h.arg_token: h.source_hint for h in prims.decision_input_hints}
    assert "buf" in hints
    assert hints["buf"] == "external"


def test_decision_input_internal_state_hint(extractor):
    body = """\
{
    if (!check_authenticated(&session)) return -1;
}"""
    prims = extractor.extract("file.c::func", body)
    hints = {h.arg_token: h.source_hint for h in prims.decision_input_hints}
    assert any(h == "internal_state" for h in hints.values())


# ──────────────────────────────────────────────────────────────
# Determinism
# ──────────────────────────────────────────────────────────────

def test_primitives_deterministic(extractor):
    body = """\
{
    if (!verify_signature(&hdr)) { return -1; }
    hdr->verified = true;
    install_firmware(buf, len);
}"""
    p1 = extractor.extract("f::g", body)
    p2 = extractor.extract("f::g", body)

    import dataclasses
    assert dataclasses.asdict(p1) == dataclasses.asdict(p2)


# ──────────────────────────────────────────────────────────────
# Integration: primitives in indexer output
# ──────────────────────────────────────────────────────────────

def test_indexer_generates_primitives_artifact(tmp_path, update_fixture_dir):
    from check_me.core.indexer import Indexer
    import json

    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()

    prim_path = tmp_path / "primitives.json"
    assert prim_path.exists()

    data = json.loads(prim_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) > 0

    # 각 entry가 필수 필드를 가지는지 확인
    for entry in data:
        assert "function_id" in entry
        assert "result_use_links" in entry
        assert "enforcement_links" in entry
        assert "state_lifecycle" in entry
        assert "decision_input_hints" in entry


def test_update_fixture_has_enforcement_links(tmp_path, update_fixture_dir):
    """update fixture의 install_with_verify 함수는 enforcement link를 가져야 한다."""
    from check_me.core.indexer import Indexer
    import json

    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    data = json.loads((tmp_path / "primitives.json").read_text(encoding="utf-8"))

    # install_with_verify 함수 찾기
    install_with_verify = next(
        (e for e in data if "install_with_verify" in e["function_id"]),
        None,
    )
    assert install_with_verify is not None, "install_with_verify function not found"
    assert len(install_with_verify["enforcement_links"]) > 0, \
        "install_with_verify should have enforcement links (guard before action)"


def test_update_fixture_bad_path_no_enforcement(tmp_path, update_fixture_dir):
    """install_without_verify 함수는 enforcement link가 없어야 한다."""
    from check_me.core.indexer import Indexer
    import json

    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    data = json.loads((tmp_path / "primitives.json").read_text(encoding="utf-8"))

    install_without = next(
        (e for e in data if "install_without_verify" in e["function_id"]),
        None,
    )
    assert install_without is not None, "install_without_verify function not found"
    assert len(install_without["enforcement_links"]) == 0, \
        "install_without_verify should NOT have enforcement links"
