"""Tests for dispatch_resolution.py — function-table dispatch
resolution edges.

The recogniser is project-agnostic: it joins ``function_table`` rows
(static array initialised with function names) with indexed-call AST
sites in the same TU, regardless of what the array or its container
is named. These tests use neutral names (``handlers``, ``ops``,
``cb``) and exercise the two recognised shapes:

  - Pattern A: ``arr[i](...)`` where ``arr`` is a known function
    table — exact match, only ``arr``'s entries are emitted.
  - Pattern B: ``obj->field[i](...)`` — struct-field dispatch where
    the static target table cannot be pinpointed; emit broad
    candidates from same-TU function tables (lossless propagation).
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


def _edges(tmp_path: Path, source: str) -> list[dict]:
    root = _project(tmp_path, {"f.c": source})
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["call_graph"]


def _resolved(edges: list[dict]) -> list[dict]:
    return [
        e
        for e in edges
        if e.get("kind") == "indirect"
        and e.get("note", "").startswith("dispatch resolved via ")
    ]


# ---------------- Pattern A: direct array dispatch ----------------


def test_direct_array_dispatch_resolves_to_exact_table(tmp_path):
    """``handlers[i](...)`` → resolved indirect edges to handlers'
    entries only; not to entries of an unrelated table in the same
    TU."""
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int alpha(int x){return x+1;}
        int beta(int x){return x+2;}
        int unrelated_a(int x){return x*7;}
        int unrelated_b(int x){return x*9;}

        static op_t handlers[] = { alpha, beta };
        static op_t unrelated[] = { unrelated_a, unrelated_b };

        int dispatch(int i, int v){
            return handlers[i](v);
        }
        """,
    )
    resolved = _resolved(edges)
    callees = {(e["callee"], e["caller"]) for e in resolved}
    assert ("alpha", "dispatch") in callees
    assert ("beta", "dispatch") in callees
    # Pattern A precision: unrelated table's entries are NOT emitted
    # for the handlers[] dispatch site.
    assert ("unrelated_a", "dispatch") not in callees
    assert ("unrelated_b", "dispatch") not in callees


def test_direct_dispatch_records_table_provenance(tmp_path):
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int one(int x){return x+1;}
        int two(int x){return x+2;}
        static op_t handlers[] = { one, two };
        int dispatch(int i){ return handlers[i](42); }
        """,
    )
    resolved = _resolved(edges)
    assert resolved
    for e in resolved:
        assert "handlers[]" in e["note"]


# ---------------- Pattern B: struct-field dispatch ----------------


def test_struct_field_dispatch_broad_matches_same_tu_tables(tmp_path):
    """``cb->callbacks[i](...)`` cannot be statically pinned to one
    table from AST shape alone — emit candidate edges to every same-
    TU function table. This is over-emit-by-design (lossless
    propagation); the verifier filters per candidate."""
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int alpha(int x){return x+1;}
        int beta(int x){return x+2;}
        static op_t handlers[] = { alpha, beta };

        struct dispatcher {
            op_t *callbacks;
            int n;
        };

        int run(struct dispatcher *cb, int i){
            return cb->callbacks[i](42);
        }
        """,
    )
    resolved = _resolved(edges)
    callees = {(e["callee"], e["caller"]) for e in resolved}
    # Both handlers entries should appear as candidate dispatch
    # targets from ``run``.
    assert ("alpha", "run") in callees
    assert ("beta", "run") in callees
    # Provenance note flags this as broad-match.
    notes = {e["note"] for e in resolved if e["caller"] == "run"}
    assert any("broad-match" in n for n in notes)


# ---------------- Negative cases ----------------


def test_no_function_tables_emits_no_resolution_edges(tmp_path):
    """When the TU has no function_table registrations, dispatch
    resolution emits nothing — even if the TU contains indexed
    calls."""
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int dispatch(op_t *table, int i){ return table[i](7); }
        """,
    )
    assert _resolved(edges) == []


def test_plain_direct_call_unaffected(tmp_path):
    """Plain direct calls remain ``kind: "direct"`` and are NOT
    annotated with a dispatch-resolution note."""
    edges = _edges(
        tmp_path,
        """
        int alpha(int x){return x+1;}
        static int (*handlers[])(int) = { alpha };
        int caller(void){ return alpha(1); }
        int via_table(void){ return handlers[0](1); }
        """,
    )
    direct = [e for e in edges if e["kind"] == "direct"]
    direct_alpha = [e for e in direct if e["callee"] == "alpha" and e["caller"] == "caller"]
    assert direct_alpha
    for e in direct_alpha:
        assert "dispatch resolved" not in e.get("note", "")


def test_function_pointer_variable_call_not_resolved(tmp_path):
    """``fp(...)`` (single function-pointer variable, not indexed)
    is NOT a dispatch site for this resolver — only indexed calls
    are. Stays as the existing un-resolved indirect edge."""
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int alpha(int x){return x+1;}
        static op_t handlers[] = { alpha };
        int run(op_t fp){ return fp(7); }
        """,
    )
    resolved = _resolved(edges)
    # ``fp(7)`` is not indexed; we should NOT emit a resolution edge
    # from ``run`` to ``alpha``.
    assert not any(
        e["caller"] == "run" and e["callee"] == "alpha" for e in resolved
    )


# ---------- Single-slot dispatch via non-table callback regs ----------


def test_function_pointer_assignment_dispatch_resolves_registered_handler(
    tmp_path,
):
    """``slot->on_data(7)`` (single function-pointer field call) is
    resolved to the handler registered via
    ``slot->on_data = on_data_handler`` — exercising
    :func:`resolve_registered_callback_dispatch_edges`'s exact-site
    match for non-table callback registrations."""
    edges = _edges(
        tmp_path,
        """
        typedef int (*op_t)(int);
        struct slot {
            op_t on_data;
        };

        int on_data_handler(int x){return x+1;}

        void install(struct slot *s){
            s->on_data = on_data_handler;
        }

        int dispatch(struct slot *slot){
            return slot->on_data(7);
        }
        """,
    )
    resolved = _resolved(edges)
    pairs = {(e["caller"], e["callee"]) for e in resolved}
    assert ("dispatch", "on_data_handler") in pairs
    # The note records the matching strategy honestly — either an
    # exact site match (when the dispatch's lvalue spelling matches
    # the registration's, e.g. both ``s->on_data``) or a suffix
    # broad match (when the lvalues differ in their base, e.g.
    # ``s->on_data`` vs ``slot->on_data``, but share the trailing
    # field name ``on_data``).
    matches = [
        e for e in resolved
        if e["caller"] == "dispatch" and e["callee"] == "on_data_handler"
    ]
    assert matches, "no resolved edge from dispatch to on_data_handler"
    assert any(
        "callback site" in e["note"] or "callback suffix" in e["note"]
        for e in matches
    )
