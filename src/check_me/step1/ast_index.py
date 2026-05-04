"""libclang TU loading and project source iteration.

Single point of contact with libclang. Per-category extractors should
not import clang.cindex directly; they receive a parsed TU and traverse
its cursor tree.

Two parsing modes:

1. With ``compile_commands.json`` — flags taken from the database.
2. Without — fall back to ``-I`` flags inferred from the project tree
   plus the user-supplied ``extra_args`` (default empty). System
   headers come from the host clang's defaults.

The fallback mode is intentionally lossy. It is enough to resolve the
project's own symbols and produce a useful call graph; it is not
guaranteed to compile every translation unit cleanly. Diagnostics are
counted and reported but do not abort.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import clang.cindex as cx


# Default libclang library on Ubuntu 24.04 / clang-18.
_DEFAULT_LIBCLANG_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/libclang-18.so.1",
    "/usr/lib/x86_64-linux-gnu/libclang.so.1",
    "/usr/lib/llvm-18/lib/libclang.so.1",
    "/usr/lib/llvm-17/lib/libclang.so.1",
)


def _ensure_libclang_loaded() -> None:
    """Pick a libclang the first time we are imported."""
    if cx.Config.loaded:
        return
    env = os.environ.get("CHECK_ME_LIBCLANG")
    if env and Path(env).exists():
        cx.Config.set_library_file(env)
        return
    for path in _DEFAULT_LIBCLANG_CANDIDATES:
        if Path(path).exists():
            cx.Config.set_library_file(path)
            return
    # Let cindex itself try its own defaults; if it fails, the
    # exception will be raised on first Index.create() call.


@dataclass(frozen=True)
class FileSpec:
    """A C/C++ source file the extractor will parse."""
    path: Path                 # absolute path on disk
    rel_path: str              # path relative to project root (used in output)
    args: tuple[str, ...]      # compiler args (excluding the file itself)


@dataclass
class ParseResult:
    """A parsed translation unit plus diagnostics summary."""
    spec: FileSpec
    tu: cx.TranslationUnit
    diagnostics: list[str] = field(default_factory=list)

    @property
    def num_errors(self) -> int:
        """Count error: AND fatal: diagnostics (fatal stops parsing the rest of
        the file, which silently truncates the AST). Counted together so
        Slice 1 reports do not understate parser breakage."""
        return sum(
            1
            for d in self.diagnostics
            if d.startswith("error:") or d.startswith("fatal:")
        )


# --------------------------------------------------------------------------- #
# Project source enumeration
# --------------------------------------------------------------------------- #


_C_EXTS = (".c",)  # C only for now; .cc/.cpp can be added later


def iter_project_sources(
    project_root: Path,
    *,
    skip_dirs: Iterable[str] = (
        "tests", "test", "examples", "doc", "docs", "build", ".git",
    ),
) -> Iterator[Path]:
    """Yield every .c file under project_root excluding test/example dirs.

    Tests and examples are skipped by default because they typically pull
    in compiler-options that the project's main build does not, which
    inflates parse-error counts without contributing to the substrate
    of the real codebase.
    """
    skip = {s.lower() for s in skip_dirs}
    for dirpath, dirnames, filenames in os.walk(project_root):
        # Mutate dirnames in place to prune traversal.
        dirnames[:] = [d for d in dirnames if d.lower() not in skip]
        for fn in sorted(filenames):
            if fn.endswith(_C_EXTS):
                yield Path(dirpath) / fn


# --------------------------------------------------------------------------- #
# Compile-arg construction
# --------------------------------------------------------------------------- #


def _project_include_dirs(project_root: Path) -> list[str]:
    """Inferred -I flags for source trees without compile_commands.json.

    Two-pass heuristic so that projects which use ``include/foo/bar.h``
    style includes (libssh, OpenSSL, many CMake projects) get an -I for
    the top-level ``include/`` directory even though it contains no .h
    files directly.

    Pass 1: any directory containing a .h file -> add it.
    Pass 2: for each such directory, add its parent IF the parent's
    name matches a conventional include-root pattern (``include``,
    ``inc``, ``headers``) or if the parent is the project root.

    Bounded to 200 entries so massive trees do not blow up the
    command line.
    """
    project_root_abs = os.path.abspath(str(project_root))

    primary: list[str] = []
    seen: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(project_root):
        if any(fn.endswith(".h") for fn in filenames):
            rel = os.path.abspath(dirpath)
            if rel not in seen:
                seen.add(rel)
                primary.append(rel)
        if len(primary) >= 200:
            break

    out = list(primary)
    out_set = set(seen)
    INCLUDE_ROOT_NAMES = {"include", "inc", "headers"}
    for d in primary:
        parent = os.path.dirname(d)
        if (
            os.path.basename(parent).lower() in INCLUDE_ROOT_NAMES
            or parent == project_root_abs
        ):
            if parent not in out_set:
                out_set.add(parent)
                out.append(parent)
        if len(out) >= 200:
            break
    return out


def _load_compile_commands(
    project_root: Path,
) -> dict[str, list[str]] | None:
    cc = project_root / "compile_commands.json"
    if not cc.is_file():
        return None
    try:
        data = json.loads(cc.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    out: dict[str, list[str]] = {}
    for entry in data:
        file = entry.get("file")
        if not file:
            continue
        # Prefer the "arguments" array; fall back to splitting "command".
        args = entry.get("arguments")
        if args is None:
            cmd = entry.get("command", "")
            args = cmd.split()
        # Drop the compiler argv[0] and the file itself (clang's parse() takes
        # the file separately, and the args list should contain only flags).
        cleaned: list[str] = []
        skip_next = False
        for a in args[1:]:
            if skip_next:
                skip_next = False
                continue
            if a == file or a.endswith(file):
                continue
            if a in ("-c", "-o"):
                # -c is irrelevant for parsing; -o expects an argument that
                # we drop too.
                if a == "-o":
                    skip_next = True
                continue
            cleaned.append(a)
        out[os.path.abspath(file)] = cleaned
    return out


def build_file_specs(
    project_root: Path,
    *,
    extra_args: Sequence[str] = (),
) -> list[FileSpec]:
    """Build the set of (file, args) pairs the extractor will parse."""
    project_root = project_root.resolve()
    cc_map = _load_compile_commands(project_root)
    fallback_args: tuple[str, ...] = tuple(
        f"-I{d}" for d in _project_include_dirs(project_root)
    ) + tuple(extra_args)

    specs: list[FileSpec] = []
    for src in iter_project_sources(project_root):
        abspath = str(src.resolve())
        if cc_map is not None and abspath in cc_map:
            args = tuple(cc_map[abspath])
        else:
            args = fallback_args
        specs.append(
            FileSpec(
                path=src.resolve(),
                rel_path=str(src.resolve().relative_to(project_root)),
                args=args,
            )
        )
    return specs


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse_file(index: cx.Index, spec: FileSpec) -> ParseResult:
    """Parse one C source into a TU. Never raises on diagnostics."""
    tu = index.parse(
        str(spec.path),
        args=list(spec.args),
        options=cx.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
    )
    diagnostics: list[str] = []
    for d in tu.diagnostics:
        sev = ("ignored", "note:", "warning:", "error:", "fatal:")[d.severity]
        loc = d.location
        loc_s = f"{loc.file}:{loc.line}" if loc.file else "?"
        diagnostics.append(f"{sev} {loc_s}: {d.spelling}")
    return ParseResult(spec=spec, tu=tu, diagnostics=diagnostics)


def make_index() -> cx.Index:
    _ensure_libclang_loaded()
    return cx.Index.create()
