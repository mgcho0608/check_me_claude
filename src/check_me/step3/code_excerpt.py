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
                continue
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
