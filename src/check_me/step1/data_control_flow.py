"""Intra-procedural data and control-flow extraction.

Three kinds of fact, matching ``schemas/substrate.v1.json``:

- ``branch``: ``if`` / ``switch`` constructs. Recorded with the line
  range of the construct and a short summary of the condition.
- ``loop``: ``for`` / ``while`` / ``do-while`` constructs.
- ``def_use``: a local ``VarDecl`` together with the *number* of
  uses observed in the same function (the use-list itself is
  summarized rather than enumerated, to keep the substrate JSON
  bounded). Cross-function uses are out of scope for Step 1's
  intra-procedural promise.

Step 1 is deterministic: every if / switch / for / while / do-while
in a project-local function definition produces one row.
Filtering "security-relevant" branches from "stylistic" ones is
downstream Step 2 reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import (
    function_name,
    in_project_location,
    iter_function_defs,
    written_form,
)
from .ast_index import ParseResult


@dataclass(frozen=True)
class DCFEntry:
    function: str
    file: str
    kind: str  # "def_use" | "branch" | "loop"
    summary: str
    line_start: int
    line_end: int

    def to_json(self) -> dict:
        return {
            "function": self.function,
            "file": self.file,
            "kind": self.kind,
            "summary": self.summary,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


# --------------------------------------------------------------------------- #
# Per-function extraction
# --------------------------------------------------------------------------- #


_BRANCH_KINDS = (cx.CursorKind.IF_STMT, cx.CursorKind.SWITCH_STMT)
_LOOP_KINDS = (
    cx.CursorKind.FOR_STMT,
    cx.CursorKind.WHILE_STMT,
    cx.CursorKind.DO_STMT,
)

# Tokens that mark a cursor as an assignment-flavour operator.
_ASSIGN_TOKENS = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
)
# Tokens that, if encountered first, prove the cursor is NOT an
# assignment (it's some other binary operator). Bare operator chars
# only — comparison and arithmetic — never appear inside an LHS for
# valid C assignments, so the first hit decides.
_NON_ASSIGN_OP_TOKENS = frozenset(
    {
        "==", "!=", "<=", ">=", "<", ">",
        "+", "-", "*", "/", "%",
        "&&", "||", "&", "|", "^",
        "<<", ">>",
    }
)


def _is_assignment_cursor(cursor: cx.Cursor) -> bool:
    if cursor.kind == cx.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
        return True
    if cursor.kind != cx.CursorKind.BINARY_OPERATOR:
        return False
    for tok in cursor.get_tokens():
        s = tok.spelling
        if s in _ASSIGN_TOKENS:
            return True
        if s in _NON_ASSIGN_OP_TOKENS:
            return False
    return False


def _extent_lines(cursor: cx.Cursor) -> tuple[int, int]:
    e = cursor.extent
    return e.start.line, e.end.line


def _branch_summary(stmt: cx.Cursor) -> str:
    if stmt.kind == cx.CursorKind.IF_STMT:
        kids = list(stmt.get_children())
        cond = kids[0] if kids else None
        cond_text = written_form(cond) if cond else "?"
        has_else = len(kids) >= 3
        return (
            f"if ({cond_text})"
            + (" with else" if has_else else "")
        )
    if stmt.kind == cx.CursorKind.SWITCH_STMT:
        kids = list(stmt.get_children())
        cond = kids[0] if kids else None
        cond_text = written_form(cond) if cond else "?"
        # Count immediate case labels by walking the body's children.
        body = kids[1] if len(kids) >= 2 else None
        n_cases = 0
        if body is not None:
            for c in body.walk_preorder():
                if c.kind == cx.CursorKind.CASE_STMT:
                    n_cases += 1
        return f"switch ({cond_text}) — {n_cases} case label(s)"
    return "branch"


def _loop_summary(stmt: cx.Cursor) -> str:
    if stmt.kind == cx.CursorKind.FOR_STMT:
        kids = list(stmt.get_children())
        # Children: optional init, optional cond, optional inc, body.
        # libclang exposes them in source order; we just describe the
        # form without trying to label which child is which.
        cond_text = "?"
        for c in kids[:-1]:
            wf = written_form(c)
            if wf and wf != "<unknown>":
                cond_text = wf
                break
        return f"for (...; {cond_text}; ...)"
    if stmt.kind == cx.CursorKind.WHILE_STMT:
        kids = list(stmt.get_children())
        cond = kids[0] if kids else None
        cond_text = written_form(cond) if cond else "?"
        return f"while ({cond_text})"
    if stmt.kind == cx.CursorKind.DO_STMT:
        kids = list(stmt.get_children())
        # do { body } while (cond) — last child is the condition.
        cond = kids[-1] if kids else None
        cond_text = written_form(cond) if cond else "?"
        return f"do {{ ... }} while ({cond_text})"
    return "loop"


def _walk_body(
    fn: cx.Cursor, fn_name: str, rel_path: str
) -> list[DCFEntry]:
    """Yield branches, loops, and local-VarDecl def_use entries inside ``fn``.

    Cursor walk is preorder over the function body. Branches/loops
    nested inside other branches/loops produce one entry each — this
    is intentional, the data is post-processed by Step 2.
    """
    out: list[DCFEntry] = []
    body_extent = fn.extent
    body_file = body_extent.start.file.name if body_extent.start.file else None

    # Per-function bookkeeping for def_use:
    #   var_decls : (decl_cursor, line) by USR (libclang stable ID)
    #   var_uses  : USR -> use count
    var_decls: dict[str, tuple[cx.Cursor, int]] = {}
    var_uses: dict[str, int] = {}

    for cur in fn.walk_preorder():
        loc = cur.location
        if loc.file is None or loc.file.name != body_file:
            # Filter cursors whose source comes from an included header
            # (the function spans the file it was defined in).
            continue
        if cur.kind in _BRANCH_KINDS:
            ls, le = _extent_lines(cur)
            out.append(
                DCFEntry(
                    function=fn_name,
                    file=rel_path,
                    kind="branch",
                    summary=_branch_summary(cur),
                    line_start=ls,
                    line_end=le,
                )
            )
        elif cur.kind in _LOOP_KINDS:
            ls, le = _extent_lines(cur)
            out.append(
                DCFEntry(
                    function=fn_name,
                    file=rel_path,
                    kind="loop",
                    summary=_loop_summary(cur),
                    line_start=ls,
                    line_end=le,
                )
            )
        elif cur.kind == cx.CursorKind.VAR_DECL:
            usr = cur.get_usr()
            if usr and usr not in var_decls:
                var_decls[usr] = (cur, loc.line)
        elif cur.kind == cx.CursorKind.DECL_REF_EXPR:
            ref = cur.referenced
            if ref is None or ref.kind != cx.CursorKind.VAR_DECL:
                continue
            usr = ref.get_usr()
            if usr in var_decls:
                var_uses[usr] = var_uses.get(usr, 0) + 1
        elif cur.kind in (
            cx.CursorKind.BINARY_OPERATOR,
            cx.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR,
        ):
            if _is_assignment_cursor(cur):
                ls, le = _extent_lines(cur)
                wf = written_form(cur)
                out.append(
                    DCFEntry(
                        function=fn_name,
                        file=rel_path,
                        kind="def_use",
                        summary=f"assign {wf}" if wf and wf != "<unknown>" else "assignment",
                        line_start=ls,
                        line_end=le,
                    )
                )

    for usr, (decl, line) in var_decls.items():
        uses = var_uses.get(usr, 0)
        var_name = decl.spelling or "<anonymous>"
        type_text = decl.type.spelling if decl.type else "?"
        out.append(
            DCFEntry(
                function=fn_name,
                file=rel_path,
                kind="def_use",
                summary=(
                    f"local {type_text} {var_name}; "
                    f"declared L{line}; {uses} use(s)"
                ),
                line_start=line,
                line_end=line,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def extract_dcf_from_tu(
    parsed: ParseResult, project_root: Path
) -> list[DCFEntry]:
    project_root_abs = str(project_root.resolve())
    out: list[DCFEntry] = []
    for fn, _rel in iter_function_defs(parsed.tu, project_root_abs):
        rel = _rel
        assert rel is not None
        out.extend(_walk_body(fn, function_name(fn), rel))
    return out


def merge_dcf(*lists: Iterable[DCFEntry]) -> list[DCFEntry]:
    """Deduplicate and sort across TUs."""
    seen: set[tuple] = set()
    out: list[DCFEntry] = []
    for lst in lists:
        for e in lst:
            key = (e.function, e.file, e.kind, e.line_start, e.line_end)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line_start, e.kind, e.function))
    return out
