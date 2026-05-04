"""Config / mode / command-trigger extraction.

Two mechanisms covered:

- ``ifdef``: preprocessor conditional directives ``#if`` / ``#ifdef``
  / ``#ifndef`` / ``#elif``. Identifiers referenced in the condition
  are emitted as `(file, line, name)` rows. Each conditional that
  references multiple identifiers (e.g. ``#if defined(A) || B``)
  produces one row per identifier.
- ``compile_flag``: ``-D<NAME>`` and ``-D<NAME>=<VALUE>`` flags
  recovered from each TU's compiler args (typically from
  ``compile_commands.json``). Each unique macro becomes one row,
  attributed to the file the flag was active for.

``cli_argument`` and ``mode_switch`` (CLI parsing idioms and switch
statements over ``mode``-like variables) are not implemented here;
recognising arbitrary CLI parsing patterns or naming-based mode
switches is heuristic-heavy and is left to future work outside the
deterministic Step 1 surface.

Output rows match ``schemas/substrate.v1.json``:

    {
      "kind": "ifdef" | "cli_argument" | "mode_switch" |
              "compile_flag" | "unknown",
      "name": str,
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

from .ast_helpers import in_project_location
from .ast_index import FileSpec, ParseResult


# --------------------------------------------------------------------------- #
# Output row
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ConfigTrigger:
    kind: str
    name: str
    file: str
    line: int
    note: str = ""

    def to_json(self) -> dict:
        d = {
            "kind": self.kind,
            "name": self.name,
            "file": self.file,
            "line": self.line,
        }
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# ifdef / #if / #ifndef / #elif source scanner
# --------------------------------------------------------------------------- #


# Match `#<spaces>if` family directives, allowing any leading whitespace.
# Group 1 = directive keyword, group 2 = remainder of the line up to a
# trailing comment or backslash-continuation.
_DIRECTIVE_RE = re.compile(
    r"^\s*#\s*(if|ifdef|ifndef|elif|elifdef|elifndef)\b(.*)$"
)
# Identifier pattern. C identifiers are [A-Za-z_][A-Za-z0-9_]*.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Tokens that should not be reported as config flags even though they
# match the identifier pattern.
_RESERVED = frozenset(
    {
        "defined",
        "not", "and", "or",  # alternative spellings sometimes seen
        "true", "false",
    }
)


def _strip_line_comments(line: str) -> str:
    """Drop `// ...` and `/* ... */` comments. Preserves text inside
    string literals trivially because preprocessor directives rarely
    contain quotes that would matter for identifier extraction."""
    # /* ... */ — only handle single-line, since the scanner is per-line.
    line = re.sub(r"/\*.*?\*/", " ", line)
    # // ...
    if "//" in line:
        line = line[: line.index("//")]
    return line


def _identifiers_in_condition(remainder: str) -> list[str]:
    """Return the order-preserving list of *unique* identifiers that
    appear in a preprocessor conditional remainder, excluding
    reserved tokens."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _IDENT_RE.finditer(remainder):
        ident = m.group(0)
        if ident in _RESERVED:
            continue
        if ident in seen:
            continue
        seen.add(ident)
        out.append(ident)
    return out


def scan_file_for_ifdefs(path: Path) -> list[tuple[str, int, str]]:
    """Read ``path`` line-by-line and return a list of
    ``(directive, line_number, condition_text)`` tuples for every
    ``#if`` / ``#ifdef`` / ``#ifndef`` / ``#elif`` line."""
    out: list[tuple[str, int, str]] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                # Handle backslash continuations by joining a few
                # extra lines (rare but valid in directives).
                line = raw.rstrip("\n")
                while line.endswith("\\"):
                    try:
                        line = line[:-1] + " " + next(fh).rstrip("\n")
                    except StopIteration:
                        line = line[:-1]
                        break
                line = _strip_line_comments(line)
                m = _DIRECTIVE_RE.match(line)
                if not m:
                    continue
                directive, remainder = m.group(1), m.group(2).strip()
                out.append((directive, lineno, remainder))
    except OSError:
        return []
    return out


def extract_ifdef_rows(
    project_root: Path, src_files: Iterable[Path]
) -> list[ConfigTrigger]:
    project_root_abs = str(project_root.resolve())
    out: list[ConfigTrigger] = []
    for src in src_files:
        abs_str = str(src.resolve())
        if not abs_str.startswith(project_root_abs):
            continue
        rel = abs_str[len(project_root_abs) + 1 :]
        for directive, line, remainder in scan_file_for_ifdefs(src):
            for ident in _identifiers_in_condition(remainder):
                out.append(
                    ConfigTrigger(
                        kind="ifdef",
                        name=ident,
                        file=rel,
                        line=line,
                        note=f"#{directive} {remainder}".rstrip(),
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# compile_flag extraction from -D arguments
# --------------------------------------------------------------------------- #


_DFLAG_RE = re.compile(r"^-D([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$")


def _macros_from_args(args: tuple[str, ...]) -> list[tuple[str, str]]:
    """Return ``(name, value)`` pairs from -D flags. Value is empty
    string when the flag has no ``=``."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    i = 0
    while i < len(args):
        a = args[i]
        m = _DFLAG_RE.match(a)
        if m:
            name = m.group(1)
            val = m.group(2) or ""
            if name not in seen:
                seen.add(name)
                out.append((name, val))
        elif a == "-D" and i + 1 < len(args):
            nxt = args[i + 1]
            mm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$", nxt)
            if mm:
                name = mm.group(1)
                val = mm.group(2) or ""
                if name not in seen:
                    seen.add(name)
                    out.append((name, val))
            i += 1
        i += 1
    return out


def extract_compile_flag_rows(
    specs: Iterable[FileSpec],
) -> list[ConfigTrigger]:
    """One row per (file, -D macro). The line number is set to 0 to
    signal "comes from build configuration, not from source"."""
    out: list[ConfigTrigger] = []
    for spec in specs:
        for name, val in _macros_from_args(spec.args):
            note = f"-D{name}" if not val else f"-D{name}={val}"
            out.append(
                ConfigTrigger(
                    kind="compile_flag",
                    name=name,
                    file=spec.rel_path,
                    line=0,
                    note=note,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def iter_project_source_and_headers(
    project_root: Path,
    *,
    skip_dirs: Iterable[str] = (
        "tests", "test", "examples", "doc", "docs", "build", ".git",
    ),
):
    """Yield every .c and .h file under ``project_root`` (skipping
    test/example dirs the same way ``ast_index.iter_project_sources``
    does). config_triggers needs headers because that is where most
    feature macros are referenced via ``#ifdef``."""
    import os

    skip = {s.lower() for s in skip_dirs}
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d.lower() not in skip]
        for fn in sorted(filenames):
            if fn.endswith((".c", ".h")):
                yield Path(dirpath) / fn


def extract_config_triggers(
    project_root: Path,
    specs: Iterable[FileSpec],
) -> list[ConfigTrigger]:
    """Extract ifdef + compile_flag rows for the project."""
    out: list[ConfigTrigger] = []
    src_files = list(iter_project_source_and_headers(project_root))
    out.extend(extract_ifdef_rows(project_root, src_files))
    out.extend(extract_compile_flag_rows(specs))
    return out


def merge_config_triggers(
    *lists: Iterable[ConfigTrigger],
) -> list[ConfigTrigger]:
    seen: set[tuple] = set()
    out: list[ConfigTrigger] = []
    for lst in lists:
        for e in lst:
            key = (e.file, e.line, e.kind, e.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.kind, e.name))
    return out
