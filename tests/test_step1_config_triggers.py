"""Pytest fixtures for step1.config_triggers primitives.

Two mechanisms covered: ifdef (preprocessor conditional directives,
detected by source-text scanning of .c and .h files) and
compile_flag (-D macros recovered from clang argument lists).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.step1 import config_triggers
from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _cfg(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    root = _project(tmp_path, files)
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["config_mode_command_triggers"]


# --------- ifdef detection ---------


def test_ifdef_emits_one_row_per_identifier(tmp_path):
    rows = _cfg(
        tmp_path,
        {
            "f.c": """\
                #ifdef ENABLE_FOO
                int x;
                #endif
                """,
        },
    )
    assert any(
        r["kind"] == "ifdef"
        and r["name"] == "ENABLE_FOO"
        and r["file"] == "f.c"
        for r in rows
    ), rows


def test_ifndef_recorded_with_directive_in_note(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#ifndef NO_NETWORK\nint x;\n#endif\n"},
    )
    r = next(r for r in rows if r["kind"] == "ifdef" and r["name"] == "NO_NETWORK")
    assert "#ifndef" in r["note"]


def test_if_defined_extracts_identifier(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#if defined(FEAT)\nint x;\n#endif\n"},
    )
    assert any(r["name"] == "FEAT" for r in rows), rows


def test_if_with_logical_or_emits_each_identifier(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#if defined(A) || defined(B)\nint x;\n#endif\n"},
    )
    names = {r["name"] for r in rows if r["kind"] == "ifdef"}
    assert {"A", "B"} <= names, rows


def test_elif_directive_extracted(tmp_path):
    rows = _cfg(
        tmp_path,
        {
            "f.c": (
                "#ifdef A\nint x;\n"
                "#elif defined(B)\nint y;\n"
                "#endif\n"
            )
        },
    )
    names = {r["name"] for r in rows if r["kind"] == "ifdef"}
    assert "A" in names and "B" in names, rows


def test_defined_keyword_itself_not_emitted_as_a_name(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#if defined(FEAT)\nint x;\n#endif\n"},
    )
    names = {r["name"] for r in rows if r["kind"] == "ifdef"}
    assert "defined" not in names


def test_ifdef_in_header_file_extracted(tmp_path):
    """Headers carry most config gates in real projects."""
    rows = _cfg(
        tmp_path,
        {
            "include/proj/feat.h": "#ifdef FEAT_X\nint x;\n#endif\n",
            "src/main.c": '#include "proj/feat.h"\nint main(void){return 0;}\n',
        },
    )
    names = [(r["file"], r["name"]) for r in rows if r["kind"] == "ifdef"]
    assert ("include/proj/feat.h", "FEAT_X") in names, rows


def test_multiple_ifdefs_in_one_file_each_one_row(tmp_path):
    rows = _cfg(
        tmp_path,
        {
            "f.c": """\
                #ifdef A
                #endif
                #ifdef B
                #endif
                #ifdef A
                #endif
                """,
        },
    )
    a_rows = [r for r in rows if r["kind"] == "ifdef" and r["name"] == "A"]
    b_rows = [r for r in rows if r["kind"] == "ifdef" and r["name"] == "B"]
    # 2 ifdef A directives means 2 rows (different lines)
    assert len(a_rows) == 2, a_rows
    assert len(b_rows) == 1, b_rows


def test_comments_stripped_from_directive_remainder(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#ifdef FEAT // enables feature\nint x;\n#endif\n"},
    )
    feat = next(r for r in rows if r["name"] == "FEAT")
    assert "//" not in feat["note"]


def test_block_comment_stripped(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": "#ifdef /* foo */ FEAT\nint x;\n#endif\n"},
    )
    assert any(r["name"] == "FEAT" for r in rows), rows


def test_non_directive_line_with_hash_not_extracted(tmp_path):
    rows = _cfg(
        tmp_path,
        {"f.c": '#include "stdio.h"\nint x;\n'},
    )
    # #include isn't an ifdef
    assert all(r["kind"] != "ifdef" or r["file"] != "f.c" or r["line"] != 1 for r in rows)


def test_ifdef_line_number_matches_directive(tmp_path):
    rows = _cfg(
        tmp_path,
        {
            "f.c": (
                "/* L1 */\n"
                "/* L2 */\n"
                "#ifdef FEAT\n"      # L3
                "int x;\n"
                "#endif\n"
            )
        },
    )
    feat = next(r for r in rows if r["name"] == "FEAT")
    assert feat["line"] == 3, feat


# --------- compile_flag detection ---------


def test_dflag_simple_macro_extracted(tmp_path):
    """A -D flag in the FileSpec args produces a compile_flag row."""
    # Construct a FileSpec by hand and exercise the helper directly.
    from check_me.step1 import ast_index

    root = _project(tmp_path, {"f.c": "int main(void){return 0;}\n"})
    specs = ast_index.build_file_specs(
        root, extra_args=("-DENABLE_FOO",)
    )
    out = config_triggers.extract_compile_flag_rows(specs)
    assert any(
        r.kind == "compile_flag" and r.name == "ENABLE_FOO" for r in out
    ), out


def test_dflag_with_value(tmp_path):
    from check_me.step1 import ast_index
    root = _project(tmp_path, {"f.c": "int main(void){return 0;}\n"})
    specs = ast_index.build_file_specs(
        root, extra_args=("-DBUFSIZE=1024",)
    )
    out = config_triggers.extract_compile_flag_rows(specs)
    r = next(r for r in out if r.name == "BUFSIZE")
    assert "BUFSIZE=1024" in r.note


def test_separate_d_argument(tmp_path):
    """Separate ``-D NAME`` (two args) is also handled."""
    from check_me.step1 import ast_index
    root = _project(tmp_path, {"f.c": "int main(void){return 0;}\n"})
    specs = ast_index.build_file_specs(
        root, extra_args=("-D", "WITH_X")
    )
    out = config_triggers.extract_compile_flag_rows(specs)
    assert any(r.name == "WITH_X" for r in out), out


def test_compile_flag_line_is_zero(tmp_path):
    """compile_flag rows do not point to a source line; convention is
    ``line: 0`` to signal "comes from build configuration"."""
    from check_me.step1 import ast_index
    root = _project(tmp_path, {"f.c": "int main(void){return 0;}\n"})
    specs = ast_index.build_file_specs(
        root, extra_args=("-DA",)
    )
    out = config_triggers.extract_compile_flag_rows(specs)
    a = next(r for r in out if r.name == "A")
    assert a.line == 0


def test_dflag_only_one_row_per_macro_per_file(tmp_path):
    """Repeated -DA on the same file collapses to one row."""
    from check_me.step1 import ast_index
    root = _project(tmp_path, {"f.c": "int main(void){return 0;}\n"})
    specs = ast_index.build_file_specs(
        root, extra_args=("-DA", "-DA")
    )
    out = config_triggers.extract_compile_flag_rows(specs)
    a_rows = [r for r in out if r.name == "A"]
    assert len(a_rows) == 1, a_rows


# --------- structural ---------


def test_deterministic_output(tmp_path):
    files = {"f.c": "#ifdef A\n#endif\n"}
    a = _cfg(tmp_path / "a", files)
    b = _cfg(tmp_path / "b", files)
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
        {"f.c": "#ifdef FEAT\nint x;\n#endif\nint main(void){return 0;}\n"},
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)
