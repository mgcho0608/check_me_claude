"""Pytest fixtures for step1.data_control_flow primitives.

Each test compiles a tiny synthetic project under tmp_path, runs the
full step1 runner, and asserts on the data_control_flow rows.
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


def _dcf(tmp_path: Path, source: str) -> list[dict]:
    root = _project(tmp_path, {"f.c": source})
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["data_control_flow"]


# ---------------- branch detection ----------------


def test_simple_if_emits_branch(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            if (x > 0) return 1;
            return 0;
        }
        """,
    )
    branches = [r for r in rows if r["kind"] == "branch"]
    assert len(branches) == 1
    b = branches[0]
    assert b["function"] == "f"
    assert "if (x > 0)" in b["summary"]
    assert b["line_start"] >= 2
    assert b["line_end"] >= b["line_start"]


def test_if_else_recorded_with_else_marker(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            if (x > 0) { return 1; } else { return 2; }
        }
        """,
    )
    b = next(r for r in rows if r["kind"] == "branch")
    assert "with else" in b["summary"]


def test_nested_if_yields_two_branches(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x, int y) {
            if (x > 0) {
                if (y > 0) return 1;
            }
            return 0;
        }
        """,
    )
    branches = [r for r in rows if r["kind"] == "branch"]
    assert len(branches) == 2


def test_switch_emits_branch_with_case_count(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            switch (x) {
                case 1: return 1;
                case 2: return 2;
                case 3: return 3;
                default: return 0;
            }
        }
        """,
    )
    sw = [r for r in rows if r["kind"] == "branch" and "switch" in r["summary"]]
    assert len(sw) == 1
    # 3 explicit cases (default is a DEFAULT_STMT, not a CASE_STMT)
    assert "3 case" in sw[0]["summary"]


# ---------------- loop detection ----------------


def test_for_loop(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int n) {
            int s = 0;
            for (int i = 0; i < n; i++) s += i;
            return s;
        }
        """,
    )
    loops = [r for r in rows if r["kind"] == "loop"]
    assert len(loops) == 1
    assert loops[0]["summary"].startswith("for")


def test_while_loop_records_condition(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int n) {
            int i = 0;
            while (i < n) i++;
            return i;
        }
        """,
    )
    loops = [r for r in rows if r["kind"] == "loop"]
    assert len(loops) == 1
    assert "while (i < n)" in loops[0]["summary"]


def test_do_while_loop(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int n) {
            int i = 0;
            do { i++; } while (i < n);
            return i;
        }
        """,
    )
    loops = [r for r in rows if r["kind"] == "loop"]
    assert len(loops) == 1
    assert "do" in loops[0]["summary"]
    assert "while" in loops[0]["summary"]


def test_nested_loops_emit_multiple_entries(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int n, int m) {
            int s = 0;
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < m; j++) {
                    s += i * j;
                }
            }
            return s;
        }
        """,
    )
    loops = [r for r in rows if r["kind"] == "loop"]
    assert len(loops) == 2


def test_loop_inside_branch(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            if (x > 0) {
                while (x--) ;
            }
            return 0;
        }
        """,
    )
    branches = [r for r in rows if r["kind"] == "branch"]
    loops = [r for r in rows if r["kind"] == "loop"]
    assert len(branches) == 1
    assert len(loops) == 1


# ---------------- def_use detection ----------------


def test_local_var_def_use_records_uses(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            int y = x + 1;
            return y * y;
        }
        """,
    )
    defs = [r for r in rows if r["kind"] == "def_use"]
    # libclang exposes both 'x' (parameter) and 'y' (local). Parameters
    # are also VarDecl-kind cursors in C, so we expect at least the
    # local 'y'.
    y_rows = [r for r in defs if " y;" in r["summary"]]
    assert len(y_rows) == 1
    assert "2 use(s)" in y_rows[0]["summary"]


def test_unused_local_recorded_with_zero_uses(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(void) {
            int dead = 0;
            return 1;
        }
        """,
    )
    defs = [r for r in rows if r["kind"] == "def_use" and " dead;" in r["summary"]]
    assert len(defs) == 1
    assert "0 use(s)" in defs[0]["summary"]


def test_def_use_includes_type_text(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(void) {
            unsigned int u = 0;
            return (int) u;
        }
        """,
    )
    defs = [r for r in rows if r["kind"] == "def_use" and " u;" in r["summary"]]
    assert len(defs) == 1
    assert "unsigned int" in defs[0]["summary"]


def test_two_locals_emit_two_def_use(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(void) {
            int a = 1;
            int b = 2;
            return a + b;
        }
        """,
    )
    defs = [
        r for r in rows
        if r["kind"] == "def_use"
        and (" a;" in r["summary"] or " b;" in r["summary"])
    ]
    assert len(defs) == 2


# ---------------- structural ----------------


def test_no_dcf_rows_for_external_headers(tmp_path):
    """Branches inside system / extra-project headers must not appear
    in the substrate."""
    rows = _dcf(
        tmp_path,
        """
        #include <stddef.h>
        int f(int n) {
            if (n) return 1;
            return 0;
        }
        """,
    )
    files_seen = {r["file"] for r in rows}
    assert files_seen == {"f.c"}, files_seen


def test_function_attribution_per_function(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int g(int x) { if (x) return 1; return 0; }
        int h(int y) { if (y) return 1; return 0; }
        """,
    )
    branches = [r for r in rows if r["kind"] == "branch"]
    funcs = {r["function"] for r in branches}
    assert funcs == {"g", "h"}


def test_deterministic_output_order(tmp_path):
    """Two runs on the same source produce byte-identical
    data_control_flow rows (Step 1 promise: same input -> same output)."""
    src = """
    int f(int x) {
        for (int i = 0; i < x; i++) {
            if (i % 2) continue;
        }
        int s = 0;
        return s;
    }
    """
    a = _dcf(tmp_path / "a", src)
    # Re-create the project under a different tmp path so file paths
    # change but rel_paths don't.
    b = _dcf(tmp_path / "b", src)
    assert a == b


def test_empty_function_yields_no_dcf_rows(tmp_path):
    rows = _dcf(tmp_path, "void f(void) {}")
    assert all(r["kind"] != "branch" and r["kind"] != "loop" for r in rows)


def test_simple_assignment_emits_def_use(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            int c;
            c = x * 2;
            return c;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert any("c = x * 2" in r["summary"] for r in assigns), assigns


def test_compound_assignment_emits_def_use(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int n) {
            int s = 0;
            s += n;
            return s;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert any("s += n" in r["summary"] for r in assigns), assigns


def test_pointer_dereference_lhs_assignment_emits_def_use(tmp_path):
    """`*p++ = *sval;` is an assignment whose LHS contains the unary
    dereference `*`. Earlier the heuristic mis-classified the leading
    `*` as a binary multiplication and returned False. This test
    pins the corrected behaviour: dereference-LHS writes are
    captured. Mirrors dnsmasq's do_rfc1035_name inner write site
    at util.c:257."""
    rows = _dcf(
        tmp_path,
        """
        void copy(char *p, const char *sval) {
            while (*sval) *p++ = *sval++;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert any(
        "*p++" in r["summary"] and "*sval" in r["summary"]
        for r in assigns
    ), assigns


def test_array_index_lhs_assignment_emits_def_use(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        void f(int *a, int n) {
            a[n] = 7;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert any("a[n] = 7" in r["summary"] for r in assigns), assigns


def test_struct_field_assignment_emits_def_use(tmp_path):
    """Mirrors libssh's session->session_state = X pattern."""
    rows = _dcf(
        tmp_path,
        """
        struct sess { int state; };
        int f(struct sess *s) {
            s->state = 42;
            return 0;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert any("s->state = 42" in r["summary"] for r in assigns), assigns


def test_comparison_does_not_emit_def_use(tmp_path):
    """``a == b`` is not an assignment, must not be counted as def_use."""
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            if (x == 0) return -1;
            return x;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert assigns == [], assigns


def test_arithmetic_does_not_emit_def_use(tmp_path):
    """``a + b`` alone (not stored anywhere) is not an assignment."""
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            return x * 2 + 1;
        }
        """,
    )
    assigns = [r for r in rows if r["kind"] == "def_use" and r["summary"].startswith("assign ")]
    assert assigns == [], assigns


def test_line_range_brackets_construct(tmp_path):
    rows = _dcf(
        tmp_path,
        """
        int f(int x) {
            if (x > 0) {
                x = x + 1;
                x = x + 2;
                x = x + 3;
            }
            return x;
        }
        """,
    )
    b = next(r for r in rows if r["kind"] == "branch")
    # The branch spans from the `if` line through the closing brace.
    assert b["line_end"] - b["line_start"] >= 4
