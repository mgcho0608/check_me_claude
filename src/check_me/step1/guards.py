"""Guard / enforcement-relation extraction.

A *guard* in the substrate is a control-flow construct whose taken
branch decides which code path runs based on a predicate or value.
The substrate captures two structurally distinct shapes:

A) ``if`` (or equivalent) whose taken branch terminates the current
   execution path — by ``return``, by ``goto`` to an explicit error
   / cleanup label, or by ``break`` / ``continue`` out of an
   enclosing loop. The condition gates fall-through code against
   the predicate.

   1. ``if (cond) return ...;``
   2. ``if (cond) goto label;``
   3. ``if (cond) break;`` / ``if (cond) continue;``
   4. ``if (cond) { return ...; }`` — single-statement compound.
   5. ``if (cond) { goto label; }``
   6. ``if (cond) { break; }`` / ``if (cond) { continue; }``

B) ``switch (expr)`` — a value-driven dispatch. Each ``case`` is a
   guard against a specific value; default is the catch-all. We
   emit ONE row per ``switch`` (with the dispatched expression as
   ``guard_call``), not per case, because the structural fact "this
   function has a switch on ``expr`` here" is what downstream
   reasoning needs. Per-case bodies are recoverable from the source
   lookup at ``(file, guard_line)``. Switch-on-attacker-byte is the
   canonical packet-dispatcher / syscall-table / event-type
   fan-out shape, generic across protocol parsers and event loops.

Forms NOT yet detected (deferred):

- ``while (cond) { ... }`` — captured as a loop in
  ``data_control_flow``, not a guard.
- Patterns like ``rc = call(); if (rc) goto err;`` — the call's
  return is checked through a temporary variable. The condition
  IS picked up (the IfStmt above), but the ``call`` itself is in
  a separate statement; this is consistent with the schema and
  no special-case is needed.

For each detected guard we emit one row with the schema fields:
``function``, ``file``, ``guard_call``, ``guard_line``,
``result_used``, ``enforcement_line``, ``note``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import (
    function_name,
    iter_function_defs,
    written_form,
)
from .ast_index import ParseResult


@dataclass(frozen=True)
class GuardEntry:
    function: str
    file: str
    guard_call: str
    guard_line: int
    result_used: bool
    enforcement_line: int | None = None
    note: str = ""

    def to_json(self) -> dict:
        d: dict = {
            "function": self.function,
            "file": self.file,
            "guard_call": self.guard_call,
            "guard_line": self.guard_line,
            "result_used": self.result_used,
        }
        if self.enforcement_line is not None:
            d["enforcement_line"] = self.enforcement_line
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# Then-branch terminator detection
# --------------------------------------------------------------------------- #


_TERMINATING_KINDS = {
    cx.CursorKind.RETURN_STMT,
    cx.CursorKind.GOTO_STMT,
    cx.CursorKind.BREAK_STMT,
    cx.CursorKind.CONTINUE_STMT,
    # Cursor for libclang-known noreturn calls would have to be
    # inferred from the callee's attributes; not done here.
}


def _is_terminating_branch(stmt: cx.Cursor) -> tuple[bool, int | None]:
    """Return (is_terminating, enforcement_line) for an if-then statement.

    ``stmt`` is the *then* cursor of an ``IfStmt``. It can be either:
    - A direct terminator (``return``, ``goto``, ``break``,
      ``continue``)
    - A compound statement whose *last* meaningful statement is a
      terminator (matches the common ``{ goto err; }`` / ``{ return
      -1; }`` pattern; intermediate logging or cleanup is allowed).

    The returned enforcement line is the line of the terminator.
    """
    if stmt is None:
        return False, None
    if stmt.kind in _TERMINATING_KINDS:
        return True, stmt.location.line
    if stmt.kind == cx.CursorKind.COMPOUND_STMT:
        last = None
        for c in stmt.get_children():
            last = c
        if last is None:
            return False, None
        return _is_terminating_branch(last)
    return False, None


# --------------------------------------------------------------------------- #
# IfStmt walker
# --------------------------------------------------------------------------- #


def _walk_if_stmts(
    fn: cx.Cursor, fn_name: str, rel_path: str
) -> list[GuardEntry]:
    out: list[GuardEntry] = []
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.IF_STMT:
            continue
        loc = cur.location
        if loc.file is None or loc.file.name != body_file:
            continue
        kids = list(cur.get_children())
        if len(kids) < 2:
            continue
        cond, then_branch = kids[0], kids[1]
        is_term, enf = _is_terminating_branch(then_branch)
        if not is_term:
            continue
        cond_text = written_form(cond) or "<unknown>"
        out.append(
            GuardEntry(
                function=fn_name,
                file=rel_path,
                guard_call=cond_text,
                guard_line=loc.line,
                result_used=True,
                enforcement_line=enf,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# SwitchStmt walker
# --------------------------------------------------------------------------- #


def _walk_switch_stmts(
    fn: cx.Cursor, fn_name: str, rel_path: str
) -> list[GuardEntry]:
    """Emit one guard row per ``switch (expr)`` in the function.

    The switch expression becomes ``guard_call`` (e.g.
    ``"switch (msg->type)"``) and the line of the switch keyword
    becomes ``guard_line``. ``enforcement_line`` is left unset
    because a switch has many candidate enforcement points (one
    per case body); recovering them is downstream Step 3 work.
    """
    out: list[GuardEntry] = []
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.SWITCH_STMT:
            continue
        loc = cur.location
        if loc.file is None or loc.file.name != body_file:
            continue
        kids = list(cur.get_children())
        if not kids:
            continue
        cond = kids[0]
        cond_text = written_form(cond) or "<unknown>"
        out.append(
            GuardEntry(
                function=fn_name,
                file=rel_path,
                guard_call=f"switch ({cond_text})",
                guard_line=loc.line,
                result_used=True,
                note="switch dispatch",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def extract_guards_from_tu(
    parsed: ParseResult, project_root: Path
) -> list[GuardEntry]:
    project_root_abs = str(project_root.resolve())
    out: list[GuardEntry] = []
    for fn, rel in iter_function_defs(parsed.tu, project_root_abs):
        assert rel is not None
        fn_name = function_name(fn)
        out.extend(_walk_if_stmts(fn, fn_name, rel))
        out.extend(_walk_switch_stmts(fn, fn_name, rel))
    return out


def merge_guards(*lists: Iterable[GuardEntry]) -> list[GuardEntry]:
    seen: set[tuple] = set()
    out: list[GuardEntry] = []
    for lst in lists:
        for e in lst:
            key = (e.function, e.file, e.guard_line, e.guard_call)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.guard_line, e.function))
    return out
