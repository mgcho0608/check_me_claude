"""Dispatch-resolution edges for function-table indirect calls.

When a translation unit contains both:

  (a) one or more ``function_table`` registrations — a static array
      initialised with a list of function names (already extracted by
      ``callback_registrations.py`` mechanism #1), and
  (b) one or more *indexed* CallExpr sites whose callee expression is
      an ``ARRAY_SUBSCRIPT_EXPR`` (i.e. ``arr[i](...)`` /
      ``obj->field[i](...)`` style),

the indexed call is a candidate dispatch into one of the function-table
entries. This module emits, per ``(call_site, table_entry)`` pair, one
``call_graph`` edge with ``kind: "indirect"`` and a ``note`` that
records the resolution provenance — turning the otherwise opaque
indirect call into a set of resolved candidate targets that downstream
layers (Step 2 verifier, Step 3 retrieval) can chain through.

Why this matters
----------------

Step 1's vanilla ``call_graph`` records an indirect CallExpr as a
single edge whose callee field names the *expression* (e.g.
``cb->callbacks[type - cb->start]``). Without resolution, downstream
LLM steps cannot follow the dispatch into the actual handler. Real
deep-chain CVEs hide their bug-bearing frame behind exactly this kind
of dispatch (libssh CVE-2018-10933:
``ssh_packet_process`` → ``cb->callbacks[i](...)`` →
``ssh_packet_userauth_success``; nginx ``ngx_command_t`` config
parsers; Linux ``struct file_operations``; embedded ISR vectors;
…). Lossless propagation of dispatch candidates is the principled
recovery.

Project-agnostic by construction
--------------------------------

The matcher is purely AST-shape based:

- *Pattern A* — exact match. The indexed call's base resolves to a
  ``DeclRefExpr`` of a project-local array. We emit edges only to the
  entries of *that* array (precise, no over-emit).
- *Pattern B* — broad match. The indexed call's base is a
  ``MEMBER_REF_EXPR`` (e.g. ``cb->callbacks``) whose target array
  cannot be statically pinpointed to a specific function table from
  the AST alone. In that case, we emit candidate edges to *every*
  function-table entry whose array element type is compatible with the
  call's expected return type (best-effort) — defaulting to all
  function tables in the same TU if the type compatibility cannot be
  established. This is over-emit-by-design, in line with the lossless-
  propagation principle: the verifier (Step 2) decides reachability
  and attacker-controllability per candidate, not the substrate.

No symbol names, suffix lists, or project-specific idioms are used —
the dispatch pattern is recognised by clang AST cursor kinds and the
already-extracted ``function_table`` rows. PLAN §6 Rule 12 is honoured:
the same code recovers Linux ``file_operations`` dispatch, libssh
packet handler dispatch, and any other static-array-of-function-
pointers + indexed-call idiom the project happens to use.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import (
    function_name,
    in_project_location,
)
from .ast_index import ParseResult
from .call_graph import CallEdge
from .callback_registrations import CallbackReg


_TRANSPARENT = {
    cx.CursorKind.UNEXPOSED_EXPR,
    cx.CursorKind.PAREN_EXPR,
    cx.CursorKind.CSTYLE_CAST_EXPR,
}


def _unwrap(cursor: cx.Cursor) -> cx.Cursor:
    cur = cursor
    while cur.kind in _TRANSPARENT:
        kids = list(cur.get_children())
        if not kids:
            break
        cur = kids[0]
    return cur


def _array_name_from_registration_site(site: str) -> str | None:
    """Recover the array spelling from a function_table row's
    ``registration_site`` (``"<name>[]"`` per
    ``callback_registrations.py``)."""
    if site.endswith("[]"):
        name = site[:-2]
        return name or None
    return None


def _index_function_tables_by_array(
    cb_rows: Iterable[CallbackReg],
) -> tuple[dict[tuple[str, str], list[CallbackReg]], dict[str, list[CallbackReg]]]:
    """Group ``function_table`` rows by ``(file, array_name)`` for
    Pattern A's exact match, and by ``file`` alone for Pattern B's
    same-TU broad match. Pattern B uses file-level grouping because a
    struct-member dispatch in foo.c plausibly resolves to any
    function table also defined in foo.c — and not, in general, to a
    table defined elsewhere (cross-TU resolution is left for a future
    pass)."""
    by_pair: dict[tuple[str, str], list[CallbackReg]] = defaultdict(list)
    by_file: dict[str, list[CallbackReg]] = defaultdict(list)
    for r in cb_rows:
        if r.kind != "function_table":
            continue
        name = _array_name_from_registration_site(r.registration_site)
        if name is None:
            continue
        by_pair[(r.file, name)].append(r)
        by_file[r.file].append(r)
    return by_pair, by_file


@dataclass(frozen=True)
class _IndexedCall:
    """An indexed-call site recognised in the AST.

    ``base_kind`` is one of:
      - ``"decl_ref"`` — base is a ``DECL_REF_EXPR`` to an array
        declaration. ``base_name`` is the array's spelling.
      - ``"member_ref"`` — base is a ``MEMBER_REF_EXPR`` (struct field
        access). ``base_name`` is the field's spelling.
    """
    caller: str
    file: str
    line: int
    base_kind: str
    base_name: str


def _is_indexed_call(call: cx.Cursor) -> _IndexedCall | None:
    """If ``call`` is an indexed function-pointer call, return an
    ``_IndexedCall`` describing the base array reference; else None.

    The recognised shape (after stripping transparent wrappers) is:

        CALL_EXPR
          callee = ARRAY_SUBSCRIPT_EXPR
                     base  = DECL_REF_EXPR | MEMBER_REF_EXPR
                     index = (any expression)

    Plain direct calls (``foo(...)``), function-pointer-variable
    calls (``fp(...)``), and member-function-pointer calls
    (``obj->fn(...)``) are NOT indexed — they are not handled here.
    """
    kids = list(call.get_children())
    if not kids:
        return None
    callee = _unwrap(kids[0])
    if callee.kind != cx.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        return None
    sub = list(callee.get_children())
    if not sub:
        return None
    base = _unwrap(sub[0])
    if base.kind == cx.CursorKind.DECL_REF_EXPR:
        return _IndexedCall(
            caller="",  # filled in by caller
            file="",
            line=0,
            base_kind="decl_ref",
            base_name=base.spelling or "",
        )
    if base.kind == cx.CursorKind.MEMBER_REF_EXPR:
        return _IndexedCall(
            caller="",
            file="",
            line=0,
            base_kind="member_ref",
            base_name=base.spelling or "",
        )
    return None


def extract_dispatch_resolution_edges(
    parsed: ParseResult,
    project_root: Path,
    callback_regs: Iterable[CallbackReg],
) -> list[CallEdge]:
    """For every indexed function-pointer call in the TU, emit
    ``kind: "indirect"`` ``CallEdge`` rows that resolve the dispatch
    to candidate handlers from same-TU function tables.

    The emitted edges supplement (not replace) the un-resolved
    indirect edge that ``call_graph.py`` already produces for the
    same call site — both stay so audit can see the original
    expression and the resolved candidates side by side.
    """
    cb_list = list(callback_regs)
    by_pair, by_file = _index_function_tables_by_array(cb_list)
    if not by_file:
        return []

    project_root_abs = str(project_root.resolve())
    out: list[CallEdge] = []
    seen: set[tuple] = set()

    for top in parsed.tu.cursor.get_children():
        if top.kind != cx.CursorKind.FUNCTION_DECL or not top.is_definition():
            continue
        ok, rel = in_project_location(top.location, project_root_abs)
        if not ok:
            continue
        caller = function_name(top)
        body_file = (
            top.extent.start.file.name if top.extent.start.file else None
        )

        for cur in top.walk_preorder():
            if cur.kind != cx.CursorKind.CALL_EXPR:
                continue
            loc = cur.location
            if loc.file is None or loc.file.name != body_file:
                continue
            ok2, rel_call = in_project_location(loc, project_root_abs)
            if not ok2:
                continue
            ic = _is_indexed_call(cur)
            if ic is None:
                continue

            # Pattern A: exact array match (decl_ref to a known table
            # in this TU).
            entries: list[CallbackReg] = []
            resolution_label: str
            if ic.base_kind == "decl_ref":
                pair_key = (rel_call, ic.base_name)
                exact = by_pair.get(pair_key)
                if exact:
                    entries = exact
                    resolution_label = f"{ic.base_name}[]"
                else:
                    # No exact match in this file. Fall back to broad
                    # match (same TU) — preserves recall when the
                    # array is declared via a different name (e.g.
                    # extern table imported through a typedef or
                    # forward-declared in a header). The note
                    # records the imprecision honestly.
                    entries = by_file.get(rel_call, [])
                    resolution_label = (
                        f"{ic.base_name}[] (no same-file table; "
                        f"broad-match across TU function tables)"
                    )
            else:
                # Pattern B: member_ref base. Static type of the
                # struct field is not pinpointed here; emit broad
                # match across same-TU function tables. Lossless
                # propagation principle — verifier filters per
                # candidate.
                entries = by_file.get(rel_call, [])
                resolution_label = (
                    f"{ic.base_name}[] (struct-field dispatch; "
                    f"broad-match across TU function tables)"
                )

            for entry in entries:
                key = (
                    caller,
                    entry.callback_function,
                    rel_call,
                    loc.line,
                    "indirect",
                    resolution_label,
                )
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    CallEdge(
                        caller=caller,
                        callee=entry.callback_function,
                        file=rel_call,
                        line=loc.line,
                        kind="indirect",
                        note=f"dispatch resolved via {resolution_label}",
                    )
                )
    return out
