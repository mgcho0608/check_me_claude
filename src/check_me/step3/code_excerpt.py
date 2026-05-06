"""Source-code excerpt extractor for Step 3.

Given a project source root and a list of ``(file, function_name)``
pairs (typically the output of :func:`step3.retrieval.compute_neighborhood`'s
nodes), pull each function's body text out of disk so it can be
embedded in the LLM synthesis prompt.

Discovery is structural: we use ``libclang`` to parse each file and
locate the matching function definition by name. The function's
body span is read directly from the file.

Project-agnostic: no symbol-name patterns, no project-name
branches. The same function-finding logic works on any C codebase
that libclang can parse.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from ..step1.ast_index import _ensure_libclang_loaded


@dataclass(frozen=True)
class FunctionExcerpt:
    function: str
    file: str
    line_start: int
    line_end: int
    body: str  # full source text of the function definition

    def to_json(self) -> dict:
        return {
            "function": self.function,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "body": self.body,
        }


# Maximum lines per function excerpt. Function bodies that exceed
# this are truncated with an ellipsis tail; the IR's evidence_anchors
# can still cite the original line range from substrate.
DEFAULT_MAX_LINES_PER_FUNCTION = 200


def _looks_like_macro_name(s: str) -> bool:
    """Return True when ``s`` looks like a C preprocessor macro
    identifier, by widely-shared K&R / Linux-kernel / POSIX
    convention: ALL_UPPERCASE_WITH_UNDERSCORES, length >= 2.

    Used to gate the macro-wrapped function-definition fallback
    below: we only fall back to children-scan when libclang's
    top-level FUNCTION_DECL spelling looks like a macro name,
    not when it's a regular identifier — so a normal function
    whose parameter happens to share a name with a wanted
    function symbol does NOT get false-matched.

    Project-agnostic — pure C identifier-shape rule. The
    convention is the C99 "Reserved identifiers" appendix +
    every major C codebase's house style (CMake macros, Linux
    kernel `EXPORT_SYMBOL`, contiki `PROCESS_THREAD`, libssh
    `SSH_PACKET_CALLBACK`, OpenSSL `IMPLEMENT_*`, nginx
    `ngx_*` macros, and so on)."""
    if len(s) < 2:
        return False
    has_upper = False
    for ch in s:
        if ch == "_" or ch.isdigit():
            continue
        if ch.isalpha():
            if not ch.isupper():
                return False
            has_upper = True
            continue
        # Non-alpha, non-digit, non-underscore — disqualifies.
        return False
    return has_upper


def _looks_like_function_identifier(s: str) -> bool:
    """Reject identifiers unlikely to name a real function —
    empty, single-character, digit-leading. Project-agnostic."""
    if not s or len(s) < 2:
        return False
    if s[0].isdigit():
        return False
    if not (s[0].isalpha() or s[0] == "_"):
        return False
    return True


def _resolve_macro_wrapped_name(
    top: cx.Cursor,
    wanted: set[str],
) -> str | None:
    """Macro-wrapped function-definition fallback.

    Some C codebases define functions through macros, e.g.::

        SSH_PACKET_CALLBACK(ssh_packet_userauth_success) {
            /* body */
        }

    libclang's mapping of the resulting FUNCTION_DECL has the
    *macro* name as ``cursor.spelling`` (``SSH_PACKET_CALLBACK``)
    and the actual function identifier appears as a child
    cursor (typically a PARM_DECL whose spelling matches the
    real function name). The same shape appears in contiki's
    ``PROCESS_THREAD(name, ev, data) { ... }`` and similar
    Linux-kernel / nginx / OpenSSL idioms.

    This helper returns the real function name iff:

      (1) ``top.spelling`` is empty or doesn't match any wanted
          (so normal FUNCTION_DECLs are unaffected by this
          fallback);
      (2) ``top.spelling`` looks like a macro name
          (`_looks_like_macro_name`, ALL_UPPERCASE convention) —
          this drops the false-match risk to near zero,
          because regular C function names are not all-caps;
      (3) one of the cursor's child identifiers (excluding
          parameter-type tokens etc.) has a spelling in
          ``wanted`` AND looks like a function identifier
          (`_looks_like_function_identifier`).

    No project / CVE / symbol-name branching — pure libclang +
    C-convention shape match, applies to any codebase using
    function-defining macros."""
    name = top.spelling or ""
    if name and name in wanted:
        return None  # Direct match — not a macro-wrapped case.
    if not _looks_like_macro_name(name):
        return None
    for child in top.get_children():
        cs = child.spelling or ""
        if not _looks_like_function_identifier(cs):
            continue
        if cs in wanted:
            return cs
    return None


def extract_excerpts(
    project_root: Path,
    targets: Iterable[tuple[str, str]],
    *,
    max_lines: int = DEFAULT_MAX_LINES_PER_FUNCTION,
    extra_clang_args: tuple[str, ...] = (),
) -> list[FunctionExcerpt]:
    """Extract function-body source for each ``(file, function)``
    target.

    ``project_root`` is the absolute or relative path to the
    project's source root (e.g. ``datasets/libssh-CVE-.../source``).
    File paths in ``targets`` are relative to this root.

    Functions that can't be located (file missing, no matching
    FunctionDecl, parse error) are skipped silently — the caller
    can detect this by comparing input length to output length.
    """
    _ensure_libclang_loaded()
    project_root = Path(project_root).resolve()

    # Group targets by file so we parse each TU at most once.
    by_file: dict[str, list[str]] = {}
    for rel, fn in targets:
        by_file.setdefault(rel, []).append(fn)

    out: list[FunctionExcerpt] = []
    index = cx.Index.create()

    for rel, fn_names in sorted(by_file.items()):
        abs_path = project_root / rel
        if not abs_path.is_file():
            continue
        wanted = set(fn_names)
        try:
            tu = index.parse(
                str(abs_path),
                args=list(extra_clang_args),
                options=cx.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
        except cx.TranslationUnitLoadError:
            continue

        try:
            with open(abs_path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        for top in tu.cursor.get_children():
            if top.kind != cx.CursorKind.FUNCTION_DECL:
                continue
            if not top.is_definition():
                continue
            name = top.spelling or ""
            if name not in wanted:
                # Macro-wrapped function definition fallback.
                # See ``_resolve_macro_wrapped_name`` for the C-
                # convention rationale; in short, codebases that
                # define functions via UPPERCASE wrapping macros
                # (libssh's SSH_PACKET_CALLBACK, contiki's
                # PROCESS_THREAD, Linux kernel macros, …) put
                # the real function name in a child cursor.
                resolved = _resolve_macro_wrapped_name(top, wanted)
                if resolved is None:
                    continue
                name = resolved
            wanted.discard(name)
            extent = top.extent
            line_start = extent.start.line
            line_end = extent.end.line
            if line_start < 1 or line_end > len(lines):
                continue
            body_lines = lines[line_start - 1: line_end]
            if len(body_lines) > max_lines:
                head = body_lines[: max_lines - 1]
                tail_marker = (
                    f"    /* ... {len(body_lines) - max_lines + 1} lines"
                    f" elided to fit prompt budget ... */\n"
                )
                body = "".join(head) + tail_marker
                line_end = line_start + max_lines - 1
            else:
                body = "".join(body_lines)
            out.append(FunctionExcerpt(
                function=name,
                file=rel,
                line_start=line_start,
                line_end=line_end,
                body=body,
            ))

    out.sort(key=lambda x: (x.file, x.line_start, x.function))
    return out
