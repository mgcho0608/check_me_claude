"""Evidence-anchor extraction.

Anchors are short pointers into source ("look at this line; here is
the structural / numeric fact you would otherwise infer from running
text"). They give downstream Step 2 / 3 layers a place to *cite* a
piece of evidence without re-reading the whole TU.

Mechanisms covered:

- ``magic_value``: ``#define NAME VALUE`` where VALUE is a numeric
  literal (decimal, hex, octal, binary). The macro's name is
  recorded in the note. Only top-level macro definitions in
  project-local files are emitted.
- ``structural_artifact``: top-level ``struct`` / ``union`` /
  ``enum`` / ``typedef`` declarations, top-level ``VarDecl``
  globals, alias macros (non-numeric ``#define`` bodies). Each
  gets a row at its declaration line; enums and structs/unions
  also emit one row per named member / field.

The remaining schema enums ``hardcoded_value`` and
``key_reference`` are deliberately not produced — they require
name-pattern heuristics (``*_KEY``, ``*_TOKEN``, embedded URLs /
paths) that overlap heavily with security-keyword scanning, which
is downstream Step 2 reasoning. The ``unknown`` enum value remains
available for any future case that does not fit the four kinds
above.

Output rows match ``schemas/substrate.v1.json``:

    {
      "kind": "hardcoded_value" | "key_reference" |
              "magic_value" | "structural_artifact" | "unknown",
      "file": str,
      "line": int,
      "note": str (optional)
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import in_project_location
from .ast_index import ParseResult


# --------------------------------------------------------------------------- #
# Output row
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Anchor:
    kind: str
    file: str
    line: int
    note: str = ""

    def to_json(self) -> dict:
        d: dict = {
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
        }
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# magic_value detection
# --------------------------------------------------------------------------- #


# A numeric token: 0x/0X hex, 0b/0B binary, 0... octal, decimal,
# possibly with U/L/UL/LL/etc. suffixes. Lookahead-tolerant.
_NUMERIC_TOKEN_RE = re.compile(
    r"""^
    (?:
        0[xX][0-9A-Fa-f_]+ |
        0[bB][01_]+        |
        0[0-9_]*           |
        [1-9][0-9_]*       |
        [0-9]*\.[0-9]+([eE][+-]?[0-9]+)?
    )
    [uUlLfF]*
    $""",
    re.VERBOSE,
)


def _is_numeric_token(token_spelling: str) -> bool:
    return bool(_NUMERIC_TOKEN_RE.match(token_spelling))


def _macro_value_tokens(decl: cx.Cursor) -> list[str]:
    """Return the value-side tokens of a ``MACRO_DEFINITION`` cursor.

    Layout: tokens are [name, value-token, value-token, ...]. We
    drop the leading name token and return the rest.
    """
    toks = [t.spelling for t in decl.get_tokens()]
    return toks[1:] if toks else []


# --------------------------------------------------------------------------- #
# structural_artifact detection
# --------------------------------------------------------------------------- #


_STRUCTURAL_KINDS = {
    cx.CursorKind.STRUCT_DECL,
    cx.CursorKind.UNION_DECL,
    cx.CursorKind.ENUM_DECL,
    cx.CursorKind.TYPEDEF_DECL,
}


def _enum_member_rows(
    enum_decl: cx.Cursor, rel_path: str
) -> list[Anchor]:
    """Emit one structural_artifact row per named enum member."""
    out: list[Anchor] = []
    for kid in enum_decl.get_children():
        if kid.kind != cx.CursorKind.ENUM_CONSTANT_DECL:
            continue
        if not kid.spelling:
            continue
        out.append(
            Anchor(
                kind="structural_artifact",
                file=rel_path,
                line=kid.location.line,
                note=f"enum member {kid.spelling}",
            )
        )
    return out


def _structural_label(decl: cx.Cursor) -> str:
    if decl.kind == cx.CursorKind.STRUCT_DECL:
        return f"struct {decl.spelling}" if decl.spelling else "anonymous struct"
    if decl.kind == cx.CursorKind.UNION_DECL:
        return f"union {decl.spelling}" if decl.spelling else "anonymous union"
    if decl.kind == cx.CursorKind.ENUM_DECL:
        return f"enum {decl.spelling}" if decl.spelling else "anonymous enum"
    if decl.kind == cx.CursorKind.TYPEDEF_DECL:
        return f"typedef {decl.spelling}"
    return "structural"


# --------------------------------------------------------------------------- #
# Public extraction
# --------------------------------------------------------------------------- #


def extract_anchors_from_tu(
    parsed: ParseResult, project_root: Path
) -> list[Anchor]:
    project_root_abs = str(project_root.resolve())
    out: list[Anchor] = []

    for top in parsed.tu.cursor.get_children():
        ok, rel = in_project_location(top.location, project_root_abs)
        if not ok:
            continue
        # Macro definition: magic_value when value is a single numeric
        # token; otherwise structural_artifact for macros that have
        # any non-trivial body (function-like macros, casts, alias
        # expressions). Empty bodies (``#define DEBUG``) are skipped.
        if top.kind == cx.CursorKind.MACRO_DEFINITION:
            value_tokens = _macro_value_tokens(top)
            if len(value_tokens) == 1 and _is_numeric_token(value_tokens[0]):
                out.append(
                    Anchor(
                        kind="magic_value",
                        file=rel,  # type: ignore[arg-type]
                        line=top.location.line,
                        note=f"#define {top.spelling} {value_tokens[0]}",
                    )
                )
            elif value_tokens:
                out.append(
                    Anchor(
                        kind="structural_artifact",
                        file=rel,  # type: ignore[arg-type]
                        line=top.location.line,
                        note=f"macro {top.spelling}",
                    )
                )
            continue
        # Structural artefacts: struct/union/enum/typedef definitions.
        if top.kind in _STRUCTURAL_KINDS:
            if top.kind in (cx.CursorKind.STRUCT_DECL, cx.CursorKind.UNION_DECL):
                if not top.is_definition():
                    continue
            out.append(
                Anchor(
                    kind="structural_artifact",
                    file=rel,  # type: ignore[arg-type]
                    line=top.location.line,
                    note=_structural_label(top),
                )
            )
            if top.kind == cx.CursorKind.ENUM_DECL and top.is_definition():
                out.extend(_enum_member_rows(top, rel))  # type: ignore[arg-type]
            # For struct/union, also emit one row per named field so
            # downstream layers can cite specific members (e.g.
            # libssh's ``session_state`` field of struct
            # ssh_session_struct).
            if top.kind in (cx.CursorKind.STRUCT_DECL, cx.CursorKind.UNION_DECL):
                for kid in top.get_children():
                    if kid.kind == cx.CursorKind.FIELD_DECL and kid.spelling:
                        out.append(
                            Anchor(
                                kind="structural_artifact",
                                file=rel,  # type: ignore[arg-type]
                                line=kid.location.line,
                                note=(
                                    f"field {kid.spelling} of "
                                    f"{_structural_label(top)}"
                                ),
                            )
                        )
            continue
        # Top-level variable declarations / definitions are
        # structural artefacts in the gold sense (e.g. contiki-ng's
        # ``uint16_t uip_len, uip_slen;`` is a security-relevant
        # global referenced throughout uip6.c).
        if top.kind == cx.CursorKind.VAR_DECL:
            type_text = top.type.spelling if top.type else "?"
            name = top.spelling or "<anonymous>"
            out.append(
                Anchor(
                    kind="structural_artifact",
                    file=rel,  # type: ignore[arg-type]
                    line=top.location.line,
                    note=f"global {type_text} {name}",
                )
            )

    return out


def merge_anchors(*lists: Iterable[Anchor]) -> list[Anchor]:
    seen: set[tuple] = set()
    out: list[Anchor] = []
    for lst in lists:
        for e in lst:
            key = (e.file, e.line, e.kind, e.note)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.kind, e.note))
    return out
