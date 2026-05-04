"""Pytest fixtures for step1.evidence_anchors primitives."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.step1 import evidence_anchors
from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _anchors(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    """Extract evidence_anchors. If the fixture supplies only header
    files, attach a one-line dummy .c that includes them so libclang
    parses a TU; the header's top-level declarations then surface in
    the TU's cursor walk just as they would in a real project."""
    files_with_c = dict(files)
    has_c = any(name.endswith(".c") for name in files_with_c)
    if not has_c:
        headers_to_include = [n for n in files_with_c if n.endswith(".h")]
        includes = "".join(f'#include "{h}"\n' for h in headers_to_include)
        files_with_c["_dummy_main.c"] = includes + "int _entry(void){return 0;}\n"
    root = _project(tmp_path, files_with_c)
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["evidence_anchors"]


# ---------- magic_value detection ----------


def test_decimal_macro_emits_magic_value(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "#define UIP_IPH_LEN 40\n"},
    )
    mag = [r for r in rows if r["kind"] == "magic_value" and "UIP_IPH_LEN" in r["note"]]
    assert len(mag) == 1
    assert mag[0]["file"] == "f.h"
    assert "40" in mag[0]["note"]


def test_hex_macro_emits_magic_value(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "#define MAGIC 0xDEADBEEF\n"},
    )
    mag = [r for r in rows if r["kind"] == "magic_value" and "MAGIC" in r["note"]]
    assert len(mag) == 1
    assert "0xDEADBEEF" in mag[0]["note"]


def test_bit_flag_macro_emits_magic_value(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "#define SSH_SESSION_FLAG_AUTHENTICATED 2\n"},
    )
    mag = [r for r in rows if "SSH_SESSION_FLAG_AUTHENTICATED" in r["note"]]
    assert len(mag) == 1
    assert mag[0]["kind"] == "magic_value"


def test_macro_without_value_skipped(tmp_path):
    """``#define DEBUG`` (no value) is not a magic_value — empty value
    token list is filtered out by the extractor."""
    rows = _anchors(
        tmp_path,
        {"f.h": "#define DEBUG\n"},
    )
    assert all(
        r["kind"] != "magic_value" or "DEBUG" not in r["note"]
        for r in rows
    )


def test_function_like_macro_skipped(tmp_path):
    """``#define MAX(a,b) ((a)>(b)?(a):(b))`` — multi-token value, not
    a magic_value but does become a structural_artifact (alias macro)."""
    rows = _anchors(
        tmp_path,
        {"f.h": "#define MAX(a,b) ((a)>(b)?(a):(b))\n"},
    )
    assert all(
        r["kind"] != "magic_value" or "MAX" not in r["note"]
        for r in rows
    )
    # The function-like macro itself surfaces as a structural_artifact.
    assert any(
        r["kind"] == "structural_artifact" and "macro MAX" in r["note"]
        for r in rows
    ), rows


def test_alias_macro_emits_structural_artifact(tmp_path):
    """Mirrors contiki-ng's ``UIP_TCP_BUF`` alias macro at uip.h:81."""
    rows = _anchors(
        tmp_path,
        {
            "f.h": (
                "struct uip_tcp_hdr {int len;};\n"
                "extern char uip_buf[];\n"
                "#define UIP_TCP_BUF ((struct uip_tcp_hdr *)(uip_buf + 40))\n"
            )
        },
    )
    assert any(
        r["kind"] == "structural_artifact" and "macro UIP_TCP_BUF" in r["note"]
        for r in rows
    ), rows


def test_global_variable_emits_structural_artifact(tmp_path):
    """Mirrors contiki-ng's ``uint16_t uip_len, uip_slen;`` global
    at uip6.c:159 — a top-level VAR_DECL is a structural anchor."""
    rows = _anchors(
        tmp_path,
        {"f.c": "unsigned short uip_len;\nint main(void){return uip_len;}\n"},
    )
    assert any(
        r["kind"] == "structural_artifact"
        and "global" in r["note"]
        and "uip_len" in r["note"]
        for r in rows
    ), rows


def test_struct_field_emits_per_field_structural_artifact(tmp_path):
    """Mirrors libssh's session.h:137 ``session_state`` field — each
    named field of a struct definition becomes its own anchor row."""
    rows = _anchors(
        tmp_path,
        {
            "f.h": (
                "enum st { S_A, S_B };\n"
                "struct sess {\n"
                "    int packet_state;\n"
                "    enum st session_state;\n"
                "};\n"
            )
        },
    )
    fields = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "field session_state" in r["note"]
    ]
    assert len(fields) == 1
    assert "struct sess" in fields[0]["note"]


def test_magic_value_line_is_directive_line(tmp_path):
    rows = _anchors(
        tmp_path,
        {
            "f.h": (
                "/* L1 */\n"
                "/* L2 */\n"
                "#define X 42  /* L3 */\n"
            )
        },
    )
    x = next(r for r in rows if "X" in r["note"] and r["kind"] == "magic_value")
    assert x["line"] == 3


# ---------- structural_artifact detection ----------


def test_typedef_emits_structural_artifact(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "typedef unsigned short uint16_t;\n"},
    )
    typed = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "typedef uint16_t" in r["note"]
    ]
    assert len(typed) == 1


def test_struct_definition_emits_structural_artifact(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "struct point { int x; int y; };\n"},
    )
    # The struct itself + one field anchor per named member.
    decl = [
        r for r in rows
        if r["kind"] == "structural_artifact" and r["note"] == "struct point"
    ]
    fields = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "field" in r["note"] and "struct point" in r["note"]
    ]
    assert len(decl) == 1
    assert {f["note"] for f in fields} == {
        "field x of struct point",
        "field y of struct point",
    }


def test_union_definition_emits_structural_artifact(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "union u { int i; float f; };\n"},
    )
    assert any(
        r["kind"] == "structural_artifact" and "union u" in r["note"]
        for r in rows
    )


def test_enum_emits_one_row_for_decl_plus_one_per_member(tmp_path):
    rows = _anchors(
        tmp_path,
        {
            "f.h": (
                "enum state {\n"
                "    STATE_NONE,\n"
                "    STATE_AUTHENTICATING,\n"
                "    STATE_AUTHENTICATED,\n"
                "};\n"
            )
        },
    )
    enum_decl = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "enum state" in r["note"]
    ]
    members = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "enum member" in r["note"]
    ]
    assert len(enum_decl) == 1
    member_names = sorted(r["note"] for r in members)
    assert member_names == [
        "enum member STATE_AUTHENTICATED",
        "enum member STATE_AUTHENTICATING",
        "enum member STATE_NONE",
    ]


def test_anonymous_struct_inside_typedef(tmp_path):
    """Anonymous struct used as a typedef target — the typedef row
    should appear, and the inner anonymous struct surfaces as a
    nested cursor that the top-level walker skips. We assert only
    on the typedef anchor."""
    rows = _anchors(
        tmp_path,
        {
            "f.h": "typedef struct { int a; int b; } pair_t;\n",
        },
    )
    typed = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "typedef pair_t" in r["note"]
    ]
    assert len(typed) == 1


def test_forward_declaration_skipped(tmp_path):
    """Pure forward decls (no body) should not produce a row — only
    actual definitions count."""
    rows = _anchors(
        tmp_path,
        {"f.h": "struct never_defined;\n"},
    )
    matching = [
        r for r in rows
        if r["kind"] == "structural_artifact" and "never_defined" in r["note"]
    ]
    assert matching == []


# ---------- structural / cross-mechanism ----------


def test_only_project_files_emit_anchors(tmp_path):
    rows = _anchors(
        tmp_path,
        {"f.h": "#define FOO 1\n"},
    )
    files_seen = {r["file"] for r in rows}
    assert files_seen == {"f.h"}


def test_combined_macro_and_struct(tmp_path):
    rows = _anchors(
        tmp_path,
        {
            "f.h": (
                "#define FLAG 4\n"
                "struct s { int x; };\n"
            )
        },
    )
    kinds = sorted({r["kind"] for r in rows})
    assert "magic_value" in kinds
    assert "structural_artifact" in kinds


def test_deterministic_output(tmp_path):
    files = {"f.h": "#define A 1\nstruct s { int x; };\n"}
    a = _anchors(tmp_path / "a", files)
    b = _anchors(tmp_path / "b", files)
    assert a == b


def test_substrate_validates_against_schema(tmp_path):
    schema_path = (
        Path(__file__).parents[1] / "schemas" / "substrate.v1.json"
    )
    if not schema_path.is_file():
        pytest.skip("schema file not present")
    schema = json.loads(schema_path.read_text())
    root = _project(
        tmp_path,
        {
            "f.h": "#define FOO 1\nstruct s { int x; };\n",
            "f.c": "int main(void){return 0;}\n",
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)


def test_numeric_token_regex_smoke(tmp_path):
    """Internal helper: numeric-token detection should accept all the
    common forms."""
    valid = [
        "0", "1", "42", "1234567",
        "0x0", "0xFF", "0xDEADBEEF", "0X10",
        "0b1010", "0B0011",
        "0755", "0123",
        "1U", "1L", "1UL", "1LL", "1ULL",
        "3.14", "3.14e10", "3.14E+0",
        "0xFF_FF",  # C23 digit separators tolerated
    ]
    for tok in valid:
        assert evidence_anchors._is_numeric_token(tok), tok
    invalid = ["", "x", "MAX", "0xZZ", "1+2", "()", "abc"]
    for tok in invalid:
        assert not evidence_anchors._is_numeric_token(tok), tok
