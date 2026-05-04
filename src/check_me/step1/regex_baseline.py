"""Naive regex-based call graph extractor — the *baseline* against
which the Clang AST extractor (``call_graph.py``) is measured.

This module exists to satisfy PLAN.md §5 Stage 0 exit criterion 1:
"Clang call graph extraction produces more edges than regex (on
same input)." It is NOT meant to be a high-quality extractor; it
is intentionally an honest reconstruction of the kind of regex
substrate the architecture P4 problem statement describes:

    Call graph built via regex despite clang AST availability.
    [...] regex (callee( pattern matching on function body text).
    The clang AST already has CallExpr nodes with precise callee
    information [...] that are discarded.

What this baseline does:

- Strip block comments / line comments / string literal contents
  while preserving line numbers (so reported lines line up with
  the original source).
- Scan top-level lines for what *looks like* a function definition
  header that ends in ``{`` (single-line or trailing-brace style).
- Skip C keywords / control-flow tokens that share the
  ``name(...)`` shape (``if``, ``for``, ``while``, ``switch``,
  ``return``, ``sizeof``, ``typeof``, ``__attribute__``, etc.).
- Use a brace-counting state machine to find the body end.
- Inside each body, find every ``name(`` token and emit a
  ``(caller, callee, file, line, kind="direct")`` row.

What this baseline cannot do (the documented limitations):

- Cannot resolve indirect calls through function pointers
  (``obj->cb(...)`` matches only as ``cb`` if at all — the
  ``->`` is silently consumed by ``\\b`` so a pure ``\\b\\w+\\s*\\(``
  often misses ``->`` chains; we do match the trailing identifier
  but the result is the *field name*, not the resolved target).
- Cannot resolve macro-expanded calls (the macro name is captured
  if it is followed by ``(``, but the expansion content is
  invisible).
- Cannot track preprocessor state — calls inside
  ``#ifdef DISABLED`` blocks are reported the same as calls in
  active code (Clang silently drops the disabled branch).
- Cannot distinguish a function declaration from a function
  definition with absolute reliability (we use the trailing
  ``{`` cue).

These are the exact gaps the Clang-AST extractor closes. The
comparison metric (this baseline vs. ``call_graph.py``) makes the
architectural decision quantitative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .call_graph import CallEdge


# --------------------------------------------------------------------------- #
# Source cleaning
# --------------------------------------------------------------------------- #


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\\n])*"')
_CHAR_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\\n])*'")


def clean_source(text: str) -> str:
    """Strip comments and replace string/char-literal *contents* with
    empty string so identifiers inside text/string literals do not
    appear as call candidates. Line numbers are preserved (every
    removed character is replaced with a newline if it was a newline,
    or with a space otherwise)."""

    def _replace_preserving_newlines(s: str) -> str:
        return "".join("\n" if c == "\n" else " " for c in s)

    def _block(m: re.Match[str]) -> str:
        return _replace_preserving_newlines(m.group(0))

    def _line(m: re.Match[str]) -> str:
        return _replace_preserving_newlines(m.group(0))

    def _str(m: re.Match[str]) -> str:
        # Keep the surrounding quotes, blank the middle.
        body = m.group(0)
        return body[0] + " " * (len(body) - 2) + body[-1]

    text = _BLOCK_COMMENT_RE.sub(_block, text)
    text = _LINE_COMMENT_RE.sub(_line, text)
    text = _STRING_LITERAL_RE.sub(_str, text)
    text = _CHAR_LITERAL_RE.sub(_str, text)
    return text


# --------------------------------------------------------------------------- #
# Function-header detection
# --------------------------------------------------------------------------- #


# Identifier pattern.
_IDENT = r"[A-Za-z_][A-Za-z_0-9]*"

# Heuristic for a function definition header on a single line ending
# with ``{``. Captures the function name (the last identifier before
# ``(``). The pattern intentionally allows several leading qualifier
# / type tokens.
_HEADER_RE = re.compile(
    r"""
    ^                                         # start of (logical) line
    [^\S\n]*                                  # leading whitespace
    (?:(?:struct|union|enum|const|volatile|static|extern|inline|register|auto|signed|unsigned)\s+)*
    (?:[A-Za-z_]\w*[\s\*]+){0,5}              # 0-5 type/qualifier tokens
    (?P<name>[A-Za-z_]\w*)                    # function name
    \s*\(                                     # opening paren
    [^{};]*                                   # arg list — no braces or semicolons
    \)
    [^{};]*                                   # post-arg qualifiers (e.g. __attribute__((...)))
    \{                                        # opening brace of body
    [^\n]*$                                   # rest of line
    """,
    re.VERBOSE | re.MULTILINE,
)


# Names that are not actual user-defined functions even though they
# fit the ``name(...)`` shape.
_RESERVED_CALL_NAMES = frozenset(
    {
        # control flow
        "if", "else", "while", "for", "do", "switch", "case",
        "default", "break", "continue", "return", "goto",
        # operators that take a parenthesised operand
        "sizeof", "typeof", "alignof", "_Alignof", "_Alignas",
        "_Static_assert", "_Generic", "_Noreturn", "_Thread_local",
        "__alignof__", "__attribute__", "__typeof__", "__extension__",
        "__asm__", "asm", "__builtin_offsetof", "offsetof",
        # type keywords / qualifiers that can appear before a paren
        "struct", "union", "enum", "typedef",
        "void", "char", "short", "int", "long", "float", "double",
        "signed", "unsigned", "_Bool", "_Complex", "_Imaginary",
        "const", "volatile", "restrict",
        "static", "extern", "inline", "register", "auto",
    }
)


# --------------------------------------------------------------------------- #
# Body scanning
# --------------------------------------------------------------------------- #


_CALL_RE = re.compile(r"\b(" + _IDENT + r")\s*\(")


def _find_function_bodies(
    text: str,
) -> list[tuple[str, int, int, int]]:
    """Return ``(name, header_line, body_start_idx, body_end_idx)``
    tuples for every detected function definition.

    ``body_start_idx`` is the offset of the ``{`` in ``text``;
    ``body_end_idx`` is the offset just past the matching ``}``.
    ``header_line`` is the 1-based source line of the header.
    """
    out: list[tuple[str, int, int, int]] = []
    for m in _HEADER_RE.finditer(text):
        name = m.group("name")
        if name in _RESERVED_CALL_NAMES:
            continue
        # ``m.end() - 1`` is the position right after the ``{`` we matched.
        # Find the matching ``}`` via brace counting.
        brace_pos = text.rfind("{", m.start(), m.end())
        if brace_pos < 0:
            continue
        depth = 1
        i = brace_pos + 1
        n = len(text)
        while i < n and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body_end_idx = i
        header_line = text.count("\n", 0, m.start()) + 1
        out.append((name, header_line, brace_pos + 1, body_end_idx - 1))
    return out


def _calls_in_range(
    text: str, start: int, end: int, base_line: int
) -> Iterable[tuple[str, int]]:
    """Yield ``(callee_name, line)`` for every ``name(`` token in
    ``text[start:end]``. Reserved names are filtered.

    ``base_line`` is the 1-based source line corresponding to
    ``text[start]`` minus the count of newlines before ``start``;
    we compute the line offset locally by counting newlines.
    """
    body = text[start:end]
    line_offsets: list[int] = [0]
    for i, ch in enumerate(body):
        if ch == "\n":
            line_offsets.append(i + 1)
    # base_line is 1-based source line of body[0]
    for m in _CALL_RE.finditer(body):
        name = m.group(1)
        if name in _RESERVED_CALL_NAMES:
            continue
        # Skip definition-style false positives where the matched
        # identifier is immediately preceded by tokens that mean it's
        # not actually a call (e.g. ``int x = NAME(args)``? — that IS
        # a call; we don't filter those). The trickier case is a
        # nested function-pointer cast like ``(*name)(...)``; we let
        # ``name`` be captured as the call target since that is what
        # the original P4 description models.
        offset = m.start()
        # Compute source line via binary search in line_offsets.
        lo, hi = 0, len(line_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        line = base_line + lo
        yield name, line


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def extract_regex_call_edges(
    file_path: Path, rel_path: str
) -> list[CallEdge]:
    """Run the regex baseline on a single file and return CallEdge
    rows. Errors silently return ``[]`` (e.g. on read errors)."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []

    cleaned = clean_source(raw)
    edges: list[CallEdge] = []
    seen: set[tuple] = set()
    for name, header_line, body_start, body_end in _find_function_bodies(
        cleaned
    ):
        for callee, line in _calls_in_range(
            cleaned, body_start, body_end, header_line
        ):
            key = (name, callee, rel_path, line)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                CallEdge(
                    caller=name,
                    callee=callee,
                    file=rel_path,
                    line=line,
                    kind="direct",
                )
            )
    return edges


def extract_regex_call_edges_for_project(
    project_root: Path,
) -> list[CallEdge]:
    """Walk the project source tree (.c only — the baseline mirrors the
    Clang extractor's scope) and return a deduplicated list of
    regex-discovered call edges sorted by ``(file, line, caller, callee)``."""
    project_root_abs = project_root.resolve()
    project_str = str(project_root_abs)
    out: list[CallEdge] = []
    seen: set[tuple] = set()
    for src in project_root_abs.rglob("*.c"):
        # Skip test / example / build dirs the same way ast_index does.
        rel = str(src).replace(project_str + "/", "", 1)
        parts = rel.lower().split("/")
        if any(p in {"tests", "test", "examples", "doc", "docs", "build"} for p in parts):
            continue
        for e in extract_regex_call_edges(src, rel):
            key = (e.caller, e.callee, e.file, e.line, e.kind)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.caller, e.callee))
    return out


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ComparisonReport:
    clang_total: int
    regex_total: int
    intersection: int
    clang_only: int
    regex_only: int
    # The strict-match key is (caller, callee, file, line); the fuzzy
    # match drops the line, useful when regex picks the wrong
    # attribution line.
    strict_match: int
    fuzzy_match: int

    def to_json(self) -> dict:
        return {
            "clang_total": self.clang_total,
            "regex_total": self.regex_total,
            "intersection_strict": self.strict_match,
            "intersection_fuzzy": self.fuzzy_match,
            "clang_only_strict": self.clang_total - self.strict_match,
            "regex_only_strict": self.regex_total - self.strict_match,
        }


def compare_edges(
    clang_edges: Iterable[CallEdge],
    regex_edges: Iterable[CallEdge],
) -> ComparisonReport:
    clang_strict = {(e.caller, e.callee, e.file, e.line) for e in clang_edges}
    regex_strict = {(e.caller, e.callee, e.file, e.line) for e in regex_edges}
    clang_fuzzy = {(c, ce, f) for (c, ce, f, _l) in clang_strict}
    regex_fuzzy = {(c, ce, f) for (c, ce, f, _l) in regex_strict}
    strict_match = len(clang_strict & regex_strict)
    fuzzy_match = len(clang_fuzzy & regex_fuzzy)
    return ComparisonReport(
        clang_total=len(clang_strict),
        regex_total=len(regex_strict),
        intersection=strict_match,
        clang_only=len(clang_strict) - strict_match,
        regex_only=len(regex_strict) - strict_match,
        strict_match=strict_match,
        fuzzy_match=fuzzy_match,
    )
