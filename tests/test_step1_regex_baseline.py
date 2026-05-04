"""Pytest fixtures for step1.regex_baseline.

These tests exercise both:

- the per-primitive correctness of the regex extractor itself
  (call detection, brace matching, comment / string stripping,
  reserved-name filtering, function header recognition);
- the comparison helper that contrasts the regex result with the
  Clang AST result.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from check_me.step1 import call_graph as cg_mod
from check_me.step1 import regex_baseline as rx
from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _regex_only(tmp_path: Path, source: str) -> list[dict]:
    """Run the regex baseline on a single-file project and return the
    serialised edges sorted by (file, line)."""
    root = _project(tmp_path, {"f.c": source})
    edges = rx.extract_regex_call_edges_for_project(root)
    return [e.to_json() for e in edges]


# ---------------- clean_source helpers ----------------


def test_clean_source_strips_block_comment_preserving_lines(tmp_path):
    src = "a;\n/* multi\nline\ncomment */\nb;\n"
    cleaned = rx.clean_source(src)
    # Newline count is preserved so reported line numbers stay valid.
    assert cleaned.count("\n") == src.count("\n")
    # The comment body identifier must be erased.
    assert "multi" not in cleaned


def test_clean_source_strips_line_comment(tmp_path):
    cleaned = rx.clean_source("a; // call_inside_comment(x)\nb;\n")
    assert "call_inside_comment" not in cleaned


def test_clean_source_blanks_string_contents(tmp_path):
    cleaned = rx.clean_source('printf("call_inside_string(x)");\n')
    # printf( must remain so the call is detected.
    assert "printf(" in cleaned
    # The identifier inside the string must NOT be visible.
    assert "call_inside_string" not in cleaned


def test_clean_source_blanks_char_literal_contents(tmp_path):
    cleaned = rx.clean_source("char c = '/'; foo();\n")
    assert "foo(" in cleaned


# ---------------- call detection inside function bodies ----------------


def test_simple_direct_call_extracted(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int helper(int x) { return x + 1; }
        int caller(int x) { return helper(x); }
        """,
    )
    assert any(
        r["caller"] == "caller" and r["callee"] == "helper" for r in rows
    ), rows


def test_two_calls_in_same_function(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int a(void) { return 0; }
        int b(void) { return 0; }
        int caller(void) { a(); return b(); }
        """,
    )
    callees = sorted(r["callee"] for r in rows if r["caller"] == "caller")
    assert callees == ["a", "b"], rows


def test_nested_calls_extracted(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int a(int);
        int b(int);
        int c(int);
        int caller(int x) { return a(b(c(x))); }
        """,
    )
    callees = sorted(r["callee"] for r in rows if r["caller"] == "caller")
    assert callees == ["a", "b", "c"], rows


def test_keyword_pseudo_calls_filtered(tmp_path):
    """`if (...)`, `for (...)`, `sizeof (...)`, etc. share the
    `name(...)` shape but must not be reported as call edges."""
    rows = _regex_only(
        tmp_path,
        """
        int a(void) { return 0; }
        int caller(int x) {
            if (x > 0) for (int i = 0; i < x; i++) (void)sizeof(int);
            return a();
        }
        """,
    )
    bad = {r["callee"] for r in rows if r["caller"] == "caller"} & {
        "if", "for", "sizeof", "while", "switch", "return",
    }
    assert bad == set(), rows
    assert any(r["callee"] == "a" for r in rows if r["caller"] == "caller"), rows


def test_call_inside_string_literal_filtered(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int log_msg(const char *m);
        int caller(void) {
            log_msg("not_a_call(x)");
            return 0;
        }
        """,
    )
    callees = {r["callee"] for r in rows if r["caller"] == "caller"}
    assert "log_msg" in callees
    assert "not_a_call" not in callees


def test_call_inside_block_comment_filtered(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int caller(void) {
            /* commented_call(x); */
            return 0;
        }
        """,
    )
    assert all(r["callee"] != "commented_call" for r in rows), rows


def test_call_inside_line_comment_filtered(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int caller(void) {
            // line_call(x);
            return 0;
        }
        """,
    )
    assert all(r["callee"] != "line_call" for r in rows), rows


# ---------------- function-definition recognition ----------------


def test_brace_counting_handles_nested_blocks(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int helper(int x) { return x; }
        int caller(int x) {
            if (x) {
                while (x) {
                    helper(x);
                    x--;
                }
            }
            return 0;
        }
        """,
    )
    # helper(x) call inside the nested while/if body is correctly
    # attributed to caller (not lost outside the function).
    assert any(
        r["caller"] == "caller" and r["callee"] == "helper" for r in rows
    ), rows


def test_function_declaration_without_body_is_not_a_function(tmp_path):
    """A function declaration ends with `;`, not `{`, so it should
    not be treated as a definition and its body should not be
    scanned for calls (there is no body)."""
    rows = _regex_only(
        tmp_path,
        """
        int extern_decl(int x);
        int defined_fn(void) { extern_decl(0); return 0; }
        """,
    )
    callers = {r["caller"] for r in rows}
    assert "extern_decl" not in callers
    assert "defined_fn" in callers


def test_static_inline_qualifiers_handled(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        static int helper(int x) { return x; }
        static inline int caller(int x) { return helper(x); }
        """,
    )
    assert any(
        r["caller"] == "caller" and r["callee"] == "helper" for r in rows
    ), rows


def test_two_top_level_functions_each_get_their_own_edges(tmp_path):
    rows = _regex_only(
        tmp_path,
        """
        int x(void) { return 0; }
        int g(void) { x(); return 0; }
        int h(void) { x(); return 0; }
        """,
    )
    pairs = sorted({(r["caller"], r["callee"]) for r in rows})
    assert ("g", "x") in pairs
    assert ("h", "x") in pairs


def test_calls_outside_functions_not_emitted(tmp_path):
    """Calls in static-array initialisers or in macros are at file
    scope. The regex baseline scans only inside detected function
    bodies; file-scope tokens that look like calls do not produce
    edges, and there is no '<file-scope>' caller."""
    rows = _regex_only(
        tmp_path,
        """
        int helper(int);
        int initialised = helper(7);   /* file-scope initialiser */
        int caller(void) { return helper(0); }
        """,
    )
    callers = {r["caller"] for r in rows}
    assert "<file-scope>" not in callers
    # caller -> helper IS extracted; the file-scope initialiser is not.
    pairs = {(r["caller"], r["callee"]) for r in rows}
    assert ("caller", "helper") in pairs
    # Make sure the initialiser's helper(7) call has not been
    # attributed to anything user-visible.
    initialiser_lines = {
        r["line"] for r in rows
        if r["callee"] == "helper" and r["caller"] != "caller"
    }
    assert initialiser_lines == set(), rows


# ---------------- limitations the test suite documents ----------------


def test_indirect_call_through_pointer_resolves_to_field_name(tmp_path):
    """`session->cb()` looks like a call to identifier `cb`; the
    regex baseline returns `cb` as the callee. Clang would report
    this as an indirect call. Documented in the regex_baseline
    module comment."""
    rows = _regex_only(
        tmp_path,
        """
        struct s { int (*cb)(int); };
        int caller(struct s *p) { return p->cb(0); }
        """,
    )
    assert any(
        r["caller"] == "caller" and r["callee"] == "cb" for r in rows
    ), rows


def test_ifdef_disabled_branch_still_scanned(tmp_path):
    """The regex baseline does not track preprocessor state. A call
    inside an `#if 0` block is still reported. This is the headline
    false-positive class the comparison metric exposes."""
    rows = _regex_only(
        tmp_path,
        """
        int helper(int);
        int caller(int x) {
        #if 0
            helper(x);   // should be invisible to a real compiler
        #endif
            return x;
        }
        """,
    )
    # The call inside #if 0 IS picked up — that is the documented
    # limitation.
    assert any(
        r["caller"] == "caller" and r["callee"] == "helper" for r in rows
    ), rows


# ---------------- comparison helper ----------------


def test_comparison_kind_discrepancy_for_pointer_param_call(tmp_path):
    """Both extractors see the call site `op(x)` where ``op`` is a
    function-pointer parameter. They agree on (caller, callee, file,
    line) so the strict intersection includes the row. The
    architectural advantage is the *kind*: Clang labels it
    ``indirect``; the regex baseline labels it ``direct``. Test
    asserts the kind discrepancy explicitly."""
    root = _project(
        tmp_path,
        {
            "f.c": (
                "typedef int (*op_t)(int);\n"
                "int dispatch(op_t op, int x){return op(x);}\n"
            )
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    clang_edges = [
        cg_mod.CallEdge(
            caller=r["caller"], callee=r["callee"], file=r["file"],
            line=r["line"], kind=r["kind"],
        )
        for r in substrate["categories"]["call_graph"]
    ]
    regex_edges = rx.extract_regex_call_edges_for_project(root)
    # Both contain the (dispatch, op) edge.
    assert any(
        e.caller == "dispatch" and e.callee == "op" and e.kind == "indirect"
        for e in clang_edges
    ), clang_edges
    assert any(
        e.caller == "dispatch" and e.callee == "op" and e.kind == "direct"
        for e in regex_edges
    ), regex_edges


def test_comparison_clang_only_when_regex_pattern_does_not_match(tmp_path):
    """A function-pointer table dispatch like `T[i](x)` does not
    match the regex baseline's `\\bname\\(` pattern at all, so the
    edge appears in clang_only / regex_only=0 for this file."""
    root = _project(
        tmp_path,
        {
            "f.c": (
                "typedef int (*op_t)(int);\n"
                "int dispatch(op_t T[], int i, int x){return T[i](x);}\n"
            )
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    clang_edges = [
        cg_mod.CallEdge(
            caller=r["caller"], callee=r["callee"], file=r["file"],
            line=r["line"], kind=r["kind"],
        )
        for r in substrate["categories"]["call_graph"]
    ]
    regex_edges = rx.extract_regex_call_edges_for_project(root)
    # Clang sees an indirect edge; regex sees zero edges in this file.
    assert any(e.kind == "indirect" for e in clang_edges), clang_edges
    assert len(regex_edges) == 0
    cmp = rx.compare_edges(clang_edges, regex_edges)
    assert cmp.clang_total > 0
    assert cmp.regex_total == 0
    assert cmp.strict_match == 0


def test_comparison_intersection_of_simple_direct_calls(tmp_path):
    """For pure direct calls in a file with no preprocessor magic,
    Clang and regex should agree on most edges. The strict match
    should cover the user-defined callers."""
    root = _project(
        tmp_path,
        {
            "f.c": (
                "int a(void){return 0;}\n"
                "int b(void){return 0;}\n"
                "int caller(void){a(); return b();}\n"
            )
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    clang_edges = [
        cg_mod.CallEdge(
            caller=r["caller"], callee=r["callee"], file=r["file"],
            line=r["line"], kind=r["kind"],
        )
        for r in substrate["categories"]["call_graph"]
    ]
    regex_edges = rx.extract_regex_call_edges_for_project(root)
    cmp = rx.compare_edges(clang_edges, regex_edges)
    # Both should find caller -> a and caller -> b.
    expected = {("caller", "a"), ("caller", "b")}
    clang_pairs = {(e.caller, e.callee) for e in clang_edges}
    regex_pairs = {(e.caller, e.callee) for e in regex_edges}
    assert expected <= clang_pairs
    assert expected <= regex_pairs
    assert cmp.fuzzy_match >= 2


def test_deterministic_baseline_output(tmp_path):
    src = (
        "int a(void){return 0;}\n"
        "int caller(void){a(); a(); return 0;}\n"
    )
    a = _regex_only(tmp_path / "a", src)
    b = _regex_only(tmp_path / "b", src)
    assert a == b
