"""Call-graph extraction from libclang TUs.

Two flavors of edge are produced:

- ``kind: "direct"`` — a ``CallExpr`` whose referenced callee is a
  named function declaration. We resolve the callee's spelling.
- ``kind: "indirect"`` — a ``CallExpr`` whose referenced expression
  evaluates to a function pointer. The callee field then names the
  pointer-typed expression as written (best-effort), and the edge is
  not resolved to a single target.

Static function-pointer dispatch tables (e.g., libssh's
``default_packet_handlers[]``, contiki-ng's
``PROCESS_THREAD``-driven event dispatch) are also indexed: each
initializer in such a table that names a function declaration becomes
a ``kind: "function_table"`` *registration* in the table-index, which
the callback_registrations extractor (Slice 3) will pick up. For
Slice 1 we just record the dispatch site as ``indirect``.

The output rows match the JSON shape required by
``schemas/substrate.v1.json#categories.call_graph``:

    {
      "caller": str,           # function spelling, or "<file-scope>"
      "callee": str,           # function spelling, or written-form for indirect
      "file": "rel/path.c",
      "line": int,
      "kind": "direct"|"indirect"|"virtual"|"unknown",
      "note": str (optional)
    }

Edges are deduplicated by the (caller, callee, file, line, kind) tuple.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import (
    function_name as _function_name,
    in_project_location,
    written_form as _written_form_helper,
)
from .ast_index import ParseResult


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    file: str
    line: int
    kind: str
    note: str = ""

    def to_json(self) -> dict:
        d = {
            "caller": self.caller,
            "callee": self.callee,
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
        }
        if self.note:
            d["note"] = self.note
        return d




def _resolve_callee(call: cx.Cursor) -> tuple[str, str]:
    """Return (callee_name, kind) for a CallExpr cursor.

    kind is one of: "direct", "indirect", "unknown".
    """
    referenced = call.referenced
    if referenced is not None and referenced.kind == cx.CursorKind.FUNCTION_DECL:
        return (referenced.spelling, "direct")
    # No directly-resolved referenced function. Walk children to look
    # for the callee expression.
    kids = list(call.get_children())
    if not kids:
        return ("<unknown>", "unknown")
    callee_expr = kids[0]
    # Common case: DeclRefExpr to a function pointer variable / table slot.
    ref = callee_expr.referenced
    if ref is not None and ref.kind == cx.CursorKind.FUNCTION_DECL:
        return (ref.spelling, "direct")
    # Otherwise treat as indirect; record the written form.
    return (_written_form_helper(callee_expr) or "<indirect>", "indirect")


def _walk_calls_in(
    decl: cx.Cursor, caller: str, project_str: str
) -> list[tuple[str, str, str, int, str]]:
    """Yield (caller, callee, rel_path, line, kind) for every CallExpr
    transitively contained in ``decl``'s body.

    Recurses into nested lambdas / nested functions (rare in C) as
    separate caller contexts — i.e., a CallExpr inside a nested
    FunctionDecl is attributed to the inner function, not the outer.
    """
    out: list[tuple[str, str, str, int, str]] = []
    for child in decl.get_children():
        if child.kind == cx.CursorKind.FUNCTION_DECL:
            # Nested function (GCC extension or similar). Switch context.
            out.extend(_walk_calls_in(child, _function_name(child), project_str))
            continue
        # Walk descendants of this child that are not function decls.
        for cur in child.walk_preorder():
            if cur.kind == cx.CursorKind.FUNCTION_DECL:
                # Boundary; skip into nested-fn handling above on the next pass.
                continue
            if cur.kind != cx.CursorKind.CALL_EXPR:
                continue
            loc = cur.location
            if loc.file is None:
                continue
            file_abs = str(Path(loc.file.name).resolve())
            if not file_abs.startswith(project_str):
                continue
            rel_path = file_abs[len(project_str) + 1 :]
            callee, kind = _resolve_callee(cur)
            out.append((caller, callee, rel_path, loc.line, kind))
    return out


def extract_call_edges_from_tu(
    parsed: ParseResult,
    project_root: Path,
) -> list[CallEdge]:
    """Walk a single TU and produce CallEdges for every CallExpr.

    Edges are filtered to those whose source location lives inside
    ``project_root`` so we do not include calls that originated in
    system or third-party headers.

    Caller attribution: top-down. For each FunctionDecl in the TU we
    walk its body and tag every CallExpr with the function's name.
    CallExprs that appear at file scope (e.g. inside a static array
    initializer or a global ``__attribute__((constructor))`` body)
    end up tagged with the most specific enclosing decl we find;
    if none is a FunctionDecl, the caller is recorded as
    ``"<file-scope>"``.
    """
    edges: list[CallEdge] = []
    seen: set[tuple] = set()
    project_root = project_root.resolve()
    project_str = str(project_root)

    raw: list[tuple[str, str, str, int, str]] = []

    for top in parsed.tu.cursor.get_children():
        # Only consider declarations originating in a project file.
        loc = top.location
        if loc.file is None:
            continue
        file_abs = str(Path(loc.file.name).resolve())
        if not file_abs.startswith(project_str):
            continue
        if top.kind == cx.CursorKind.FUNCTION_DECL and top.is_definition():
            raw.extend(_walk_calls_in(top, _function_name(top), project_str))
        else:
            # CallExprs at file scope (rare — array initializers can
            # technically not contain calls in C, but
            # __attribute__((constructor)) functions exist as separate
            # FunctionDecls and are handled above). Cover the edge
            # cases by walking with caller="<file-scope>".
            for cur in top.walk_preorder():
                if cur.kind == cx.CursorKind.FUNCTION_DECL:
                    continue
                if cur.kind != cx.CursorKind.CALL_EXPR:
                    continue
                cl = cur.location
                if cl.file is None:
                    continue
                f_abs = str(Path(cl.file.name).resolve())
                if not f_abs.startswith(project_str):
                    continue
                rel_path = f_abs[len(project_str) + 1 :]
                callee, kind = _resolve_callee(cur)
                raw.append(("<file-scope>", callee, rel_path, cl.line, kind))

    for caller, callee, rel_path, line, kind in raw:
        key = (caller, callee, rel_path, line, kind)
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            CallEdge(
                caller=caller,
                callee=callee,
                file=rel_path,
                line=line,
                kind=kind,
            )
        )
    return edges


def merge_edges(*edge_lists: Iterable[CallEdge]) -> list[CallEdge]:
    """Deduplicate across translation units.

    Same (caller, callee, file, line, kind) appearing in multiple TUs
    (e.g. an inline function defined in a header and exercised by
    several .c files) is collapsed to one row.
    """
    seen: set[tuple] = set()
    out: list[CallEdge] = []
    for lst in edge_lists:
        for e in lst:
            key = (e.caller, e.callee, e.file, e.line, e.kind)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.caller, e.callee))
    return out
