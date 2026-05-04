"""Callback-registration extraction.

Six distinct registration mechanisms are detected, each populating
the schema's ``kind`` enum:

1. ``function_table`` — a static array initialized with a list of
   function names (e.g. a packet-handler dispatch table). Each
   function-reference slot in the initializer becomes one row.

2. ``function_pointer_assignment`` — an assignment whose left-hand
   side is a writable expression of function-pointer type and whose
   right-hand side names a function (e.g.
   ``session->socket_callbacks.data = ssh_packet_socket_callback``).

3. ``signal_handler`` — a call to ``signal`` (POSIX) or
   ``bsd_signal`` / ``sysv_signal`` whose second argument is the
   handler function. ``sigaction`` registrations almost always
   route through a struct-field assignment of the handler into
   ``struct sigaction.sa_handler``; that case is picked up by the
   function_pointer_assignment path above.

4. ``constructor`` — a FunctionDecl whose attributes include
   ``constructor`` or ``destructor`` (GCC / clang
   ``__attribute__``).

5. ``struct_initializer`` — a global / static ``VarDecl`` of struct
   (or union, or array-of-struct) type whose initializer contains a
   function-decl reference in one of its fields. This is the C
   vtable-registration idiom: ``struct file_operations fops = {
   .read = my_read, .write = my_write };`` (Linux kernel),
   ``struct ngx_command_t cmds[] = { { ..., my_set_handler, ... } };``
   (nginx), ``struct process p = { NULL, "name", thread_fn };``
   (Contiki PROCESS macro expansion). Captured by AST shape, never
   by macro name.

6. ``callback_argument`` — a function passed as an argument to
   another function call. Every C standard / POSIX function that
   takes a function pointer as a parameter falls under this — the
   callee will (synchronously or asynchronously) invoke the passed
   function, so the call site IS the registration.
   ``pthread_create(..., start_fn, ...)``, ``atexit(cleanup_fn)``,
   ``qsort(..., cmp_fn)``, ``ftw(path, walker_fn, ...)``, project-
   specific helpers like ``register_event_handler(my_handler)``
   are all caught by the same shape (any CallExpr arg that resolves
   to a FunctionDecl). Signal API calls are excluded — they are
   already a more-specific kind 3.

Per ``schemas/substrate.v1.json`` each row carries:

    {
      "registration_site": str,          # written form of the LHS,
                                         # the array name, the
                                         # signal() call, or
                                         # "<attribute>"
      "callback_function": str,          # the name of the function
                                         # being registered
      "file": str,
      "line": int,                       # registration site line
      "kind": one of the four above,
      "note": str
    }
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


# --------------------------------------------------------------------------- #
# Output row
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CallbackReg:
    registration_site: str
    callback_function: str
    file: str
    line: int
    kind: str
    note: str = ""

    def to_json(self) -> dict:
        d = {
            "registration_site": self.registration_site,
            "callback_function": self.callback_function,
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
        }
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _unwrap_expr(cursor: cx.Cursor) -> cx.Cursor:
    """Strip parenthesization / implicit casts / unexposed wrappers
    until we hit a meaningful expression cursor."""
    cur = cursor
    transparent = {
        cx.CursorKind.UNEXPOSED_EXPR,
        cx.CursorKind.PAREN_EXPR,
        cx.CursorKind.CSTYLE_CAST_EXPR,
    }
    while cur.kind in transparent:
        kids = list(cur.get_children())
        if not kids:
            break
        cur = kids[0]
    return cur


def _resolved_function(cursor: cx.Cursor) -> str | None:
    """If ``cursor`` is (after unwrapping) a DeclRefExpr to a
    FunctionDecl, return the function's spelling. Else ``None``."""
    inner = _unwrap_expr(cursor)
    if inner.kind == cx.CursorKind.DECL_REF_EXPR:
        ref = inner.referenced
        if ref is not None and ref.kind == cx.CursorKind.FUNCTION_DECL:
            return ref.spelling
    return None


_TRANSPARENT_PASSTHROUGH = {
    cx.CursorKind.UNEXPOSED_EXPR,
    cx.CursorKind.PAREN_EXPR,
    cx.CursorKind.CSTYLE_CAST_EXPR,
    cx.CursorKind.INIT_LIST_EXPR,
}


# --------------------------------------------------------------------------- #
# Mechanism 1: function tables (top-level static arrays)
# --------------------------------------------------------------------------- #


def _extract_function_tables(
    parsed: ParseResult, project_root_str: str
) -> list[CallbackReg]:
    out: list[CallbackReg] = []
    for top in parsed.tu.cursor.get_children():
        if top.kind != cx.CursorKind.VAR_DECL:
            continue
        ok, rel = in_project_location(top.location, project_root_str)
        if not ok:
            continue
        if not top.type.spelling.endswith("]"):  # array type
            continue
        # Find the InitListExpr child.
        init_list = None
        for kid in top.get_children():
            if kid.kind == cx.CursorKind.INIT_LIST_EXPR:
                init_list = kid
                break
        if init_list is None:
            continue
        array_name = top.spelling or "<anonymous>"
        for slot_idx, slot in enumerate(init_list.get_children()):
            fn_name = _resolved_function(slot)
            if fn_name is None:
                continue
            out.append(
                CallbackReg(
                    registration_site=f"{array_name}[]",
                    callback_function=fn_name,
                    file=rel,  # type: ignore[arg-type]
                    line=slot.location.line,
                    kind="function_table",
                    note=f"slot index {slot_idx} of array {array_name}",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Mechanism 2: function-pointer assignments inside function bodies
# --------------------------------------------------------------------------- #


def _is_function_pointer_type(type_text: str) -> bool:
    """True if the type spelling looks like a function pointer.

    Primary signal is the syntactic ``(*`` substring; this matches
    raw function-pointer types after typedef expansion via
    ``cursor.type.get_canonical()``.

    A small fallback set of suffixes catches typedef'd aliases when
    canonicalization is unavailable (e.g. a typedef whose definition
    was not visible during parsing). The suffixes are restricted to
    those that conventionally indicate a callback role
    (``_cb``, ``_callback``, ``_handler``, ``_fn``) — broader
    suffixes like ``_t`` and ``_data`` were rejected because they
    appear on many non-function-pointer typedefs and would inject
    false positives that bias the extractor toward whatever project
    happens to use those names. The contract is to be project-
    agnostic, not to maximize gold match on any one dataset.
    """
    t = type_text.strip()
    if "(*" in t:
        return True
    if t.endswith("(*)"):  # rare but valid
        return True
    callback_suffixes = ("_cb", "_callback", "_handler", "_fn")
    return any(t.endswith(s) for s in callback_suffixes)


def _lhs_is_callback_target(lhs: cx.Cursor) -> bool:
    """Best-effort check that ``lhs`` is a writable target whose type
    is a function pointer.

    Tries the lhs's own type spelling first, then the canonical
    (typedef-expanded) type. Typedef'd function-pointer aliases
    such as libssh's ``ssh_callback_data`` only become syntactically
    visible after canonicalization.
    """
    t = lhs.type
    if _is_function_pointer_type(t.spelling):
        return True
    try:
        canon = t.get_canonical()
    except Exception:  # pragma: no cover - defensive
        canon = None
    if canon is not None and _is_function_pointer_type(canon.spelling):
        return True
    return False


def _walk_assignments_for_fn_ptr(
    fn: cx.Cursor, rel_path: str
) -> list[CallbackReg]:
    out: list[CallbackReg] = []
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.BINARY_OPERATOR:
            continue
        if cur.location.file is None or cur.location.file.name != body_file:
            continue
        kids = list(cur.get_children())
        if len(kids) < 2:
            continue
        # Confirm it's an `=` (not `==` etc.)
        is_assign = False
        for tok in cur.get_tokens():
            s = tok.spelling
            if s == "=":
                is_assign = True
                break
            if s in (
                "==", "!=", "<=", ">=", "<", ">",
                "+", "-", "*", "/", "%",
                "&&", "||", "&", "|", "^",
                "<<", ">>",
                "+=", "-=", "*=", "/=", "%=",
                "&=", "|=", "^=", "<<=", ">>=",
            ):
                break
        if not is_assign:
            continue
        lhs, rhs = kids[0], kids[1]
        # RHS must reference a FunctionDecl after unwrapping.
        fn_name = _resolved_function(rhs)
        if fn_name is None:
            continue
        # LHS should be a writable target whose type looks like a
        # function pointer (raw or typedef-aliased).
        if not _lhs_is_callback_target(lhs):
            continue
        site = written_form(lhs) or "<lhs>"
        out.append(
            CallbackReg(
                registration_site=site,
                callback_function=fn_name,
                file=rel_path,
                line=cur.location.line,
                kind="function_pointer_assignment",
                note=f"assigned in {function_name(fn)}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Mechanism 3: signal handler registrations
# --------------------------------------------------------------------------- #


_SIGNAL_APIS = {"signal", "bsd_signal", "sysv_signal"}


def _walk_signal_handlers(
    fn: cx.Cursor, rel_path: str
) -> list[CallbackReg]:
    out: list[CallbackReg] = []
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.CALL_EXPR:
            continue
        if cur.location.file is None or cur.location.file.name != body_file:
            continue
        ref = cur.referenced
        if ref is None or ref.kind != cx.CursorKind.FUNCTION_DECL:
            continue
        if ref.spelling not in _SIGNAL_APIS:
            continue
        # Children: [callee_expr, arg0 (signum), arg1 (handler)]
        kids = list(cur.get_children())
        if len(kids) < 3:
            continue
        handler = kids[2]
        fn_name = _resolved_function(handler)
        if fn_name is None:
            continue
        out.append(
            CallbackReg(
                registration_site=f"{ref.spelling}() in {function_name(fn)}",
                callback_function=fn_name,
                file=rel_path,
                line=cur.location.line,
                kind="signal_handler",
                note=f"signal API: {ref.spelling}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Mechanism 5: struct / union / array-of-struct initializers with fp fields
# --------------------------------------------------------------------------- #


def _outer_init_admits_struct_walk(t: cx.Type) -> bool:
    """True if a top-level VarDecl of type ``t`` should be walked for
    function-pointer fields. Walks structs, unions, and arrays whose
    element type is a struct/union (the array-of-struct vtable
    pattern). Plain arrays of function pointers are handled by
    mechanism 1 — we exclude them here to avoid duplicate rows."""
    canon = t.get_canonical()
    if canon.kind in (cx.TypeKind.RECORD,):
        return True
    if canon.kind == cx.TypeKind.CONSTANTARRAY:
        elem = canon.get_array_element_type().get_canonical()
        return elem.kind == cx.TypeKind.RECORD
    return False


def _walk_init_for_function_refs(
    node: cx.Cursor,
) -> Iterable[cx.Cursor]:
    """Recursively yield DECL_REF_EXPR cursors that resolve to a
    FunctionDecl, found anywhere inside ``node``'s subtree.

    Designated initialisers in libclang's AST take the shape
    ``INIT_LIST_EXPR -> UNEXPOSED_EXPR -> [MEMBER_REF, UNEXPOSED_EXPR
    -> DECL_REF_EXPR]`` — i.e. the designator and the value are
    siblings under an unexposed wrapper. A naive "follow the first
    child" unwrap therefore misses the value side. We walk *all*
    children recursively, stopping descent at CALL_EXPR /
    BINARY_OPERATOR so we don't pick up function references that
    appear inside expressions which *use* a function rather than
    *register* it (a constant initialised via ``f() + 1`` would
    otherwise mis-register ``f``)."""
    if node is None:
        return
    if node.kind == cx.CursorKind.DECL_REF_EXPR:
        ref = node.referenced
        if ref is not None and ref.kind == cx.CursorKind.FUNCTION_DECL:
            yield node
        return
    if node.kind in (
        cx.CursorKind.CALL_EXPR,
        cx.CursorKind.BINARY_OPERATOR,
    ):
        return
    for kid in node.get_children():
        yield from _walk_init_for_function_refs(kid)


def _extract_struct_initializers(
    parsed: ParseResult, project_root_str: str
) -> list[CallbackReg]:
    out: list[CallbackReg] = []
    for top in parsed.tu.cursor.get_children():
        if top.kind != cx.CursorKind.VAR_DECL:
            continue
        ok, rel = in_project_location(top.location, project_root_str)
        if not ok:
            continue
        if not _outer_init_admits_struct_walk(top.type):
            continue
        # Find the InitListExpr child. Skip if absent (e.g. extern
        # decls without initializer).
        init_list = None
        for kid in top.get_children():
            if kid.kind == cx.CursorKind.INIT_LIST_EXPR:
                init_list = kid
                break
        if init_list is None:
            continue
        var_name = top.spelling or "<anonymous>"
        seen_lines: set[tuple[int, str]] = set()
        for ref_cursor in _walk_init_for_function_refs(init_list):
            ref = ref_cursor.referenced
            if ref is None or ref.kind != cx.CursorKind.FUNCTION_DECL:
                continue
            fn_name = ref.spelling
            line = ref_cursor.location.line
            key = (line, fn_name)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            out.append(
                CallbackReg(
                    registration_site=f"{var_name}{{}}",
                    callback_function=fn_name,
                    file=rel,  # type: ignore[arg-type]
                    line=line,
                    kind="struct_initializer",
                    note=f"function-pointer field of {var_name}",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Mechanism 6: function-as-argument in a call (POSIX-style registration)
# --------------------------------------------------------------------------- #


def _walk_callback_arguments(
    fn: cx.Cursor, rel_path: str
) -> list[CallbackReg]:
    """Emit one row per function-decl reference that appears as an
    argument to a CallExpr. Generic — fires on any standard /
    POSIX function that takes a function-pointer parameter
    (``pthread_create``, ``atexit``, ``qsort``, ``bsearch``,
    ``ftw``, ``nftw``, ``pthread_atfork``, ``pthread_cleanup_push``)
    and on any project-internal registration helper of the same
    shape (``register_handler(my_fn)``,
    ``schedule_callback(cb, arg)``, ...). The signal API names are
    skipped because they are already covered by the more-specific
    ``signal_handler`` mechanism."""
    out: list[CallbackReg] = []
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.CALL_EXPR:
            continue
        if cur.location.file is None or cur.location.file.name != body_file:
            continue
        kids = list(cur.get_children())
        if not kids:
            continue
        # First child is the callee expression; remaining are args.
        callee_ref = cur.referenced
        callee_name = (
            callee_ref.spelling
            if callee_ref is not None
            and callee_ref.kind == cx.CursorKind.FUNCTION_DECL
            else "<callee>"
        )
        # Skip APIs already handled by mechanism 3 to avoid noisy
        # duplication of the same registration under two kinds.
        if callee_name in _SIGNAL_APIS:
            continue
        for arg_idx, arg in enumerate(kids[1:]):
            fn_name = _resolved_function(arg)
            if fn_name is None:
                continue
            out.append(
                CallbackReg(
                    registration_site=f"{callee_name}() arg {arg_idx}",
                    callback_function=fn_name,
                    file=rel_path,
                    line=cur.location.line,
                    kind="callback_argument",
                    note=f"passed to {callee_name} in {function_name(fn)}",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Mechanism 4: constructor / destructor attributes
# --------------------------------------------------------------------------- #


def _attribute_keywords(decl: cx.Cursor) -> set[str]:
    """Return the set of GCC-style attribute keywords attached to
    ``decl``. Reads the declaration's tokens and collects identifiers
    that follow ``__attribute__`` openings."""
    kws: set[str] = set()
    tokens = list(decl.get_tokens())
    in_attr = 0
    for i, tok in enumerate(tokens):
        s = tok.spelling
        if s == "__attribute__":
            in_attr = 2  # expect the next two `(` to enter the attr list
            continue
        if in_attr and s == "(":
            in_attr -= 1
            if in_attr == 0:
                # Now we are inside the inner `(`. Collect identifiers
                # until matching `)`.
                depth = 1
                j = i + 1
                while j < len(tokens) and depth > 0:
                    s2 = tokens[j].spelling
                    if s2 == "(":
                        depth += 1
                    elif s2 == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    elif s2.isidentifier():
                        kws.add(s2)
                    j += 1
                in_attr = 0
        elif in_attr and s == "{":
            # Reached the function body without seeing a complete
            # __attribute__((...)) — bail.
            break
    return kws


def _extract_constructor_attrs(
    parsed: ParseResult, project_root_str: str
) -> list[CallbackReg]:
    out: list[CallbackReg] = []
    for top in parsed.tu.cursor.get_children():
        if top.kind != cx.CursorKind.FUNCTION_DECL:
            continue
        if not top.is_definition():
            continue
        ok, rel = in_project_location(top.location, project_root_str)
        if not ok:
            continue
        kws = _attribute_keywords(top)
        for marker in ("constructor", "destructor"):
            if marker in kws:
                out.append(
                    CallbackReg(
                        registration_site=f"__attribute__(({marker}))",
                        callback_function=function_name(top),
                        file=rel,  # type: ignore[arg-type]
                        line=top.location.line,
                        kind="constructor",
                        note=marker,
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def extract_callback_regs_from_tu(
    parsed: ParseResult, project_root: Path
) -> list[CallbackReg]:
    project_root_abs = str(project_root.resolve())
    out: list[CallbackReg] = []
    out.extend(_extract_function_tables(parsed, project_root_abs))
    out.extend(_extract_struct_initializers(parsed, project_root_abs))
    out.extend(_extract_constructor_attrs(parsed, project_root_abs))
    for fn, rel in iter_function_defs(parsed.tu, project_root_abs):
        assert rel is not None
        out.extend(_walk_assignments_for_fn_ptr(fn, rel))
        out.extend(_walk_signal_handlers(fn, rel))
        out.extend(_walk_callback_arguments(fn, rel))
    return out


def merge_callback_regs(
    *lists: Iterable[CallbackReg],
) -> list[CallbackReg]:
    seen: set[tuple] = set()
    out: list[CallbackReg] = []
    for lst in lists:
        for e in lst:
            key = (e.file, e.line, e.kind, e.callback_function, e.registration_site)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.kind, e.callback_function))
    return out
