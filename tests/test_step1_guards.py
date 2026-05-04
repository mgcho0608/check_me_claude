"""Pytest fixtures for step1.guards primitives.

Each test compiles a tiny synthetic project under tmp_path, runs the
full step1 runner, and asserts on the guards rows.

Definition under test: a *guard* is an ``if`` whose taken branch
terminates the current execution path (return / goto / break /
continue, possibly inside a single-branch compound). See guards.py
for the full list of supported forms.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _guards(tmp_path: Path, source: str) -> list[dict]:
    root = _project(tmp_path, {"f.c": source})
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["guards"]


# ----------- positive cases: terminating forms -----------


def test_if_return_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            if (x < 0) return -1;
            return x;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["function"] == "f"
    assert g[0]["guard_call"] == "x < 0"
    assert g[0]["result_used"] is True
    assert g[0]["enforcement_line"] == g[0]["guard_line"]


def test_if_goto_label_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            if (!x) goto err;
            return 0;
        err:
            return -1;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["guard_call"] == "!x"


def test_if_break_in_loop_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int n) {
            for (int i = 0; i < n; i++) {
                if (i == 5) break;
            }
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["guard_call"] == "i == 5"


def test_if_continue_in_loop_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int n) {
            int s = 0;
            for (int i = 0; i < n; i++) {
                if (i % 2) continue;
                s += i;
            }
            return s;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["guard_call"] == "i % 2"


def test_compound_then_with_terminator_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            if (x < 0) {
                return -1;
            }
            return x;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["guard_call"] == "x < 0"


def test_compound_then_with_logging_then_terminator_is_a_guard(tmp_path):
    """If the compound's last meaningful stmt is a terminator, the
    construct still counts as a guard. Allows ``{ log(); goto err; }``."""
    g = _guards(
        tmp_path,
        """
        int log_msg(const char*);
        int f(int x) {
            if (x < 0) {
                log_msg("oops");
                return -1;
            }
            return x;
        }
        """,
    )
    assert len(g) == 1


# ----------- positive cases: condition forms -----------


def test_function_call_in_condition_preserved(tmp_path):
    g = _guards(
        tmp_path,
        """
        int validate(int);
        int f(int x) {
            if (validate(x) != 0) return -1;
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert "validate(x)" in g[0]["guard_call"]


def test_compound_boolean_condition_preserved(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x, int y) {
            if (x < 0 || y > 100) return -1;
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert "x < 0" in g[0]["guard_call"]
    assert "y > 100" in g[0]["guard_call"]


def test_pointer_null_check_is_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int *p) {
            if (p == 0) return -1;
            return *p;
        }
        """,
    )
    assert len(g) == 1
    assert "p == 0" in g[0]["guard_call"]


def test_dereference_check_is_a_guard(tmp_path):
    """Mirrors dnsmasq's ``if (truncp && *truncp) return 0;`` pattern."""
    g = _guards(
        tmp_path,
        """
        int f(int *truncp) {
            if (truncp && *truncp) return 0;
            return 1;
        }
        """,
    )
    assert len(g) == 1
    assert "truncp" in g[0]["guard_call"]
    assert "*truncp" in g[0]["guard_call"]


def test_underflow_style_length_check(tmp_path):
    """Mirrors contiki-ng uip6.c:1120 ``if (uip_len < UIP_IPH_LEN)``."""
    g = _guards(
        tmp_path,
        """
        #define UIP_IPH_LEN 40
        int f(int uip_len) {
            if (uip_len < UIP_IPH_LEN) return 1;
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert "UIP_IPH_LEN" in g[0]["guard_call"]


# ----------- negative cases: NOT guards -----------


def test_if_with_non_terminating_then_is_not_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            int y = 0;
            if (x > 0) y = 1;
            return y;
        }
        """,
    )
    assert g == []


def test_if_else_without_terminator_is_not_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            int y;
            if (x > 0) y = 1; else y = 0;
            return y;
        }
        """,
    )
    assert g == []


def test_while_loop_alone_is_not_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int n) {
            int i = 0;
            while (i < n) i++;
            return i;
        }
        """,
    )
    assert g == []


def test_switch_emits_one_guard_row_with_switch_call_in_guard_call(tmp_path):
    """A ``switch (expr)`` is a value-driven dispatch — generic across
    protocol parsers, syscall tables, and event loops. We capture
    one row per switch (the structural fact that this function
    dispatches on ``expr`` here); per-case bodies are downstream
    work."""
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            int r = 0;
            switch (x) {
                case 1: r = 1; break;
                default: r = 0; break;
            }
            return r;
        }
        """,
    )
    assert len(g) == 1, g
    row = g[0]
    assert row["function"] == "f"
    assert row["guard_call"].startswith("switch (")
    assert "x" in row["guard_call"]
    assert row["result_used"] is True


def test_compound_then_without_final_terminator_is_not_a_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int log_msg(const char*);
        int f(int x) {
            if (x < 0) {
                log_msg("warn");
                /* fall through to normal path */
            }
            return x;
        }
        """,
    )
    assert g == []


# ----------- structural / cross-function -----------


def test_two_functions_each_with_one_guard(tmp_path):
    g = _guards(
        tmp_path,
        """
        int g(int x) { if (x < 0) return -1; return x; }
        int h(int y) { if (y > 100) return -1; return y; }
        """,
    )
    assert len(g) == 2
    funcs = sorted(r["function"] for r in g)
    assert funcs == ["g", "h"]


def test_nested_guards_each_recorded(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x, int y) {
            if (x < 0) return -1;
            if (y < 0) return -2;
            return x + y;
        }
        """,
    )
    assert len(g) == 2
    lines = sorted(r["guard_line"] for r in g)
    assert lines == sorted(set(lines))


def test_guard_inside_loop(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int n, int *a) {
            for (int i = 0; i < n; i++) {
                if (a[i] < 0) return -1;
            }
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert "a[i] < 0" in g[0]["guard_call"]


def test_guard_inside_else_branch_is_recorded(tmp_path):
    """An if inside an else clause whose then-branch terminates is its
    own guard."""
    g = _guards(
        tmp_path,
        """
        int f(int x, int y) {
            if (x > 0) {
                /* normal */;
            } else {
                if (y < 0) return -1;
            }
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert "y < 0" in g[0]["guard_call"]


def test_external_header_guards_are_not_emitted(tmp_path):
    """Guards from system headers must not appear in the substrate."""
    g = _guards(
        tmp_path,
        """
        #include <stddef.h>
        int f(int *p) {
            if (p == NULL) return -1;
            return 0;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["file"] == "f.c"


def test_guard_line_matches_if_statement(tmp_path):
    g = _guards(
        tmp_path,
        """
        int f(int x) {
            int t = 1;          /* line 3 */
            if (x < 0)          /* line 4 */
                return -1;      /* line 5 */
            return t;
        }
        """,
    )
    assert len(g) == 1
    assert g[0]["guard_line"] == 4
    assert g[0]["enforcement_line"] == 5


def test_deterministic_output(tmp_path):
    src = """
    int f(int x, int y) {
        if (x < 0) return -1;
        if (y < 0) return -2;
        return x + y;
    }
    """
    a = _guards(tmp_path / "a", src)
    b = _guards(tmp_path / "b", src)
    assert a == b


def test_guards_substrate_validates_against_schema(tmp_path):
    import json
    import pytest as _pytest

    schema_path = (
        Path(__file__).parents[1] / "schemas" / "substrate.v1.json"
    )
    if not schema_path.is_file():
        _pytest.skip("schema file not present")
    schema = json.loads(schema_path.read_text())
    root = _project(
        tmp_path,
        {"f.c": "int f(int x){if(x<0)return -1;return x;}"},
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    jsonschema = _pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)
