"""Trust-boundary extraction.

A *trust boundary* in the substrate is a function whose body
directly invokes a known external-I/O API. The function is the
syntactic boundary at which attacker- or environment-controlled
bytes first cross into project code.

Per ``schemas/substrate.v1.json`` the row is:

    {
      "kind": "network_socket" | "ipc_endpoint" | "file_read" |
              "external_io" | "unknown",
      "function": str,
      "file": str,
      "line": int,                      # function decl line
      "direction": "untrusted_to_trusted" |
                   "trusted_to_untrusted" | "unknown",
      "note": str                       # short justification
    }

Detection is rule-based: a curated map of POSIX / common-libc API
names to ``(kind, direction)``. A function emits one boundary row
per ``(kind, direction)`` it exercises (so a function that does
both ``recvmsg`` and ``sendmsg`` produces two rows: one
``untrusted_to_trusted`` and one ``trusted_to_untrusted``, both
``network_socket``).

Step 1's promise stays narrow: we record *syntactic* boundaries.
Logical boundaries reached via callbacks, indirect dispatch, or
project-internal abstraction (a function installed under a
network-callback slot but which never itself calls ``recvmsg``) are
recovered downstream by joining this category's rows with the
``callback_registrations`` substrate; the join is a deterministic
substrate operation, not LLM reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import clang.cindex as cx

from .ast_helpers import function_name, iter_function_defs
from .ast_index import ParseResult


# --------------------------------------------------------------------------- #
# API table
# --------------------------------------------------------------------------- #


# Each entry: API name -> (kind, direction).
# Names matched by exact spelling against the CallExpr's referenced
# FunctionDecl. Macros that expand to these (e.g. ``recv()`` wrapped
# by some project macro) are usually invisible at this layer; the
# CallExpr's referenced cursor follows the macro expansion already.

_NETWORK_INPUT = {
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "accept", "accept4",
}
_NETWORK_OUTPUT = {
    "send", "sendto", "sendmsg", "sendmmsg",
}
_NETWORK_NEUTRAL = {
    # Setup-side calls; alone do not characterize a boundary direction
    # but they do mark the function as networking-aware.
    "socket", "bind", "listen", "connect",
    "setsockopt", "getsockopt",
}

_FILE_INPUT = {
    "read", "pread", "readv",
    "fread", "fgets", "fgetc", "getline", "getdelim",
}
_FILE_OUTPUT = {
    "write", "pwrite", "writev",
    "fwrite", "fputs", "fputc",
}
_FILE_OPEN = {
    "open", "openat", "fopen", "freopen", "creat",
}

_IPC_INPUT = {
    "mq_receive", "msgrcv", "shm_open",
    "popen",  # opens a process with bidirectional pipe; reading from
              # the resulting FILE* yields untrusted bytes.
}
_IPC_OUTPUT = {
    "mq_send", "msgsnd",
}
_IPC_SETUP = {
    "pipe", "pipe2",
    "socketpair",  # POSIX, creates a connected socket pair.
    "mkfifo", "mkfifoat",  # POSIX named pipe creation.
}

_EXTERNAL_INPUT = {
    "getenv", "secure_getenv",
    "getlogin", "getlogin_r",  # POSIX, login-name strings from env.
    "getpass",  # SUSv2, prompted password input.
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
}
_EXTERNAL_GENERIC = {
    "ioctl", "fcntl",
}

# mmap can map a file or device whose contents are attacker-influenced;
# treat as file_read with unknown direction (the kind of access depends
# on the prot flags, which we don't analyse statically).
_FILE_OPEN_MMAP = {"mmap", "mmap64"}

# (kind, direction) per API.
API_TABLE: dict[str, tuple[str, str]] = {}
for n in _NETWORK_INPUT:
    API_TABLE[n] = ("network_socket", "untrusted_to_trusted")
for n in _NETWORK_OUTPUT:
    API_TABLE[n] = ("network_socket", "trusted_to_untrusted")
for n in _NETWORK_NEUTRAL:
    API_TABLE[n] = ("network_socket", "unknown")
for n in _FILE_INPUT:
    API_TABLE[n] = ("file_read", "untrusted_to_trusted")
for n in _FILE_OUTPUT:
    API_TABLE[n] = ("file_read", "trusted_to_untrusted")
for n in _FILE_OPEN:
    API_TABLE[n] = ("file_read", "unknown")
for n in _IPC_INPUT:
    API_TABLE[n] = ("ipc_endpoint", "untrusted_to_trusted")
for n in _IPC_OUTPUT:
    API_TABLE[n] = ("ipc_endpoint", "trusted_to_untrusted")
for n in _IPC_SETUP:
    API_TABLE[n] = ("ipc_endpoint", "unknown")
for n in _EXTERNAL_INPUT:
    API_TABLE[n] = ("external_io", "untrusted_to_trusted")
for n in _EXTERNAL_GENERIC:
    API_TABLE[n] = ("external_io", "unknown")
for n in _FILE_OPEN_MMAP:
    API_TABLE[n] = ("file_read", "unknown")


# --------------------------------------------------------------------------- #
# Output row
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TrustBoundary:
    kind: str
    function: str
    file: str
    line: int
    direction: str
    note: str = ""

    def to_json(self) -> dict:
        d = {
            "kind": self.kind,
            "function": self.function,
            "file": self.file,
            "line": self.line,
            "direction": self.direction,
        }
        if self.note:
            d["note"] = self.note
        return d


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def _api_calls_in_function(fn: cx.Cursor) -> dict[tuple[str, str], list[tuple[str, int]]]:
    """Return a map (kind, direction) -> list of (api_name, line) for the
    matched API calls inside ``fn``'s body."""
    out: dict[tuple[str, str], list[tuple[str, int]]] = {}
    body_file = fn.extent.start.file.name if fn.extent.start.file else None
    for cur in fn.walk_preorder():
        if cur.kind != cx.CursorKind.CALL_EXPR:
            continue
        if cur.location.file is None or cur.location.file.name != body_file:
            continue
        ref = cur.referenced
        if ref is None or ref.kind != cx.CursorKind.FUNCTION_DECL:
            continue
        api = ref.spelling
        if api not in API_TABLE:
            continue
        kd = API_TABLE[api]
        out.setdefault(kd, []).append((api, cur.location.line))
    return out


def _is_main_with_argv(fn: cx.Cursor) -> bool:
    """C standard ``int main(int argc, char *argv[])`` — argv is the
    canonical command-line attacker-controlled input. Project-
    agnostic: any C program's main() with a second parameter is the
    CLI entry. We only require the name and >= 2 parameters; we do
    not enforce the exact ``char **`` type because some projects
    declare it ``const char * const argv[]`` and we want both."""
    if (fn.spelling or "") != "main":
        return False
    params = list(fn.get_arguments())
    return len(params) >= 2


def extract_trust_boundaries_from_tu(
    parsed: ParseResult, project_root: Path
) -> list[TrustBoundary]:
    project_root_abs = str(project_root.resolve())
    out: list[TrustBoundary] = []
    for fn, rel in iter_function_defs(parsed.tu, project_root_abs):
        assert rel is not None
        fn_name = function_name(fn)
        fn_line = fn.location.line

        api_hits = _api_calls_in_function(fn)
        for (kind, direction), hits in api_hits.items():
            sample = ", ".join(f"{a}@L{ln}" for a, ln in hits[:3])
            extra = "" if len(hits) <= 3 else f" (+{len(hits) - 3} more)"
            note = f"via {sample}{extra}"
            out.append(
                TrustBoundary(
                    kind=kind,
                    function=fn_name,
                    file=rel,
                    line=fn_line,
                    direction=direction,
                    note=note,
                )
            )

        if _is_main_with_argv(fn):
            out.append(
                TrustBoundary(
                    kind="external_io",
                    function=fn_name,
                    file=rel,
                    line=fn_line,
                    direction="untrusted_to_trusted",
                    note="argv of main() — command-line input is attacker-controlled",
                )
            )
    return out


def merge_trust_boundaries(
    *lists: Iterable[TrustBoundary],
) -> list[TrustBoundary]:
    seen: set[tuple] = set()
    out: list[TrustBoundary] = []
    for lst in lists:
        for e in lst:
            key = (e.function, e.file, e.line, e.kind, e.direction)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    out.sort(key=lambda e: (e.file, e.line, e.kind, e.direction))
    return out
