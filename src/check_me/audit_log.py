"""Stream-only audit log for long-running Step 2/3/4 calls.

Each per-call result (verifier verdict, miner chunk, IR synthesis,
scenario chunk) is appended to a JSONL file the moment it
completes. The file is purely a *log* — the runner does NOT read
it on subsequent invocations. If a process is killed mid-run, the
file preserves whatever completed for post-mortem inspection or
manual recovery; nothing is auto-resumed.

Why stream-only and not auto-resume:

  Auto-resume would make the JSONL part of the program's state
  machine — substrate-hash invalidation, partial-line recovery,
  concurrent-execution detection, LLM non-determinism handling,
  per-step granularity decisions — all become correctness-
  critical. Stream-only gives ~70% of the value (work preserved,
  audit trail, real-time progress) at ~30% of the cost.
  Auto-resume can be layered on later when 1st-round experimental
  data shows the actual failure modes.

Format: JSONL — one JSON object per line, append-only. Each
record automatically gets a UTC ISO8601 ``ts`` field. The
``stage`` field identifies which step / phase emitted the record
so a single shared log file can mix multiple stages safely.

Concurrency: writes are serialised via an internal
``threading.Lock`` so 8 parallel verifier workers can append
freely without interleaving lines.

Project-agnostic: this module reasons only about file I/O and
JSON serialisation; no project-specific logic.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    """Thread-safe append-only JSONL writer.

    Constructed with a path (or ``None`` to disable). Each call
    to :meth:`append` writes one JSON object as a line, with a
    ``ts`` field stamped at write time.

    The class is intentionally minimal: no buffering, no rotation,
    no schema validation. The caller controls what fields go in
    each record. A single :class:`AuditLog` instance is safe to
    share across threads.

    When ``path`` is ``None`` all calls are no-ops — useful for
    tests and for callers that opt out of audit logging.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        """Append one record. ``ts`` is added automatically.

        The write is atomic at the line level on POSIX
        filesystems for line lengths under PIPE_BUF (~4KB). For
        larger lines the lock prevents interleaving across
        threads. Two separate processes appending to the same
        file is NOT supported by this class — operationally, one
        run = one log file. Process-level interlock (lockfile,
        per-run subdirectory) is the operator's responsibility.
        """
        if self.path is None:
            return
        # Stamp at write time (not at record-build time) so the
        # log accurately reflects when the per-call result
        # crossed the I/O boundary.
        stamped = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            **record,
        }
        line = json.dumps(stamped, ensure_ascii=False) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)

    @classmethod
    def disabled(cls) -> "AuditLog":
        """Return a no-op log. Useful default when callers don't
        opt into audit logging."""
        return cls(path=None)


def default_audit_path(out_path: Path, stage: str) -> Path:
    """Derive a default audit-log path from a step's output path.

    Same directory, name = ``<stage>_audit.jsonl``. Example:
    ``out/foo/entrypoints.json`` + stage=``step2`` →
    ``out/foo/step2_audit.jsonl``.
    """
    return out_path.parent / f"{stage}_audit.jsonl"
