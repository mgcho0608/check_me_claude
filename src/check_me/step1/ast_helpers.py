"""Shared AST utilities for Step 1 extractors.

These helpers are purposely thin so each per-category extractor stays
self-contained and easy to test. No category-specific logic lives here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import clang.cindex as cx


# --------------------------------------------------------------------------- #
# Function-decl helpers
# --------------------------------------------------------------------------- #


def function_name(decl: cx.Cursor) -> str:
    """Stable human name for a FunctionDecl. ``"<anonymous>"`` if missing."""
    return decl.spelling or decl.displayname or "<anonymous>"


def iter_function_defs(
    tu: cx.TranslationUnit, project_root_str: str
) -> Iterator[tuple[cx.Cursor, str]]:
    """Yield ``(decl, rel_path)`` for every project-local function
    *definition* in the TU.

    Forward declarations and functions whose location lives outside
    ``project_root_str`` (system or third-party headers) are skipped.
    """
    for top in tu.cursor.get_children():
        if top.kind != cx.CursorKind.FUNCTION_DECL:
            continue
        if not top.is_definition():
            continue
        ok, rel = in_project_location(top.location, project_root_str)
        if not ok:
            continue
        yield top, rel  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Source-location helpers
# --------------------------------------------------------------------------- #


def in_project_location(
    loc: cx.SourceLocation, project_root_str: str
) -> tuple[bool, str | None]:
    """Return ``(in_project, rel_path)``.

    ``rel_path`` is ``None`` when the location lies outside
    ``project_root_str`` or when the location has no associated file
    (e.g. built-in macros).
    """
    if loc.file is None:
        return False, None
    file_abs = str(Path(loc.file.name).resolve())
    if not file_abs.startswith(project_root_str):
        return False, None
    return True, file_abs[len(project_root_str) + 1 :]


# --------------------------------------------------------------------------- #
# Source-text recovery
# --------------------------------------------------------------------------- #


def written_form(cursor: cx.Cursor, *, max_len: int = 200) -> str:
    """Best-effort textual form of an AST cursor's source span.

    Multi-line spans are collapsed onto a single line by joining with a
    space and squeezing repeated whitespace. Returns ``"<unknown>"``
    if the source file cannot be read.

    The result is truncated to ``max_len`` characters with a trailing
    ellipsis so substrate JSON payloads stay bounded.
    """
    extent = cursor.extent
    try:
        path = extent.start.file.name
    except AttributeError:
        return "<unknown>"
    if path is None:
        return "<unknown>"
    try:
        # Some legacy C trees ship sources with mixed encodings (e.g.
        # latin-1 in contiki-ng's TI cc26xx vendor blobs). errors='replace'
        # keeps the recovery best-effort without aborting Step 1.
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return "<unknown>"

    s, e = extent.start, extent.end
    if s.line < 1 or e.line > len(lines):
        return "<unknown>"

    if s.line == e.line:
        out = lines[s.line - 1][s.column - 1 : e.column - 1]
    else:
        first = lines[s.line - 1][s.column - 1 :].rstrip("\n")
        middle = [lines[ln - 1].strip() for ln in range(s.line + 1, e.line)]
        last = lines[e.line - 1][: e.column - 1].rstrip("\n")
        out = " ".join(p for p in (first, *middle, last) if p)
    out = " ".join(out.split())  # squeeze whitespace
    if len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out
