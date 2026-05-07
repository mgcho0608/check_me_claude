"""Pytest for audit_log — stream-only JSONL writer."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from check_me.audit_log import AuditLog, default_audit_path


def test_append_writes_one_line_per_call(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append({"stage": "step2.verifier", "verdict": "kept"})
    log.append({"stage": "step2.verifier", "verdict": "quarantined"})

    lines = p.read_text().splitlines()
    assert len(lines) == 2
    a = json.loads(lines[0])
    b = json.loads(lines[1])
    assert a["verdict"] == "kept"
    assert b["verdict"] == "quarantined"


def test_append_stamps_ts(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append({"foo": "bar"})
    record = json.loads(p.read_text())
    assert "ts" in record
    # ISO8601 UTC ending in Z. Format produced by the helper.
    assert record["ts"].endswith("Z")
    assert "T" in record["ts"]


def test_append_creates_parent_dir(tmp_path: Path) -> None:
    p = tmp_path / "nested" / "deeper" / "audit.jsonl"
    log = AuditLog(p)
    log.append({"x": 1})
    assert p.is_file()


def test_disabled_log_is_noop(tmp_path: Path) -> None:
    """``AuditLog.disabled()`` must accept appends without writing
    anywhere — used as the default when callers don't opt in."""
    log = AuditLog.disabled()
    # Many appends; none should raise or create files.
    for i in range(50):
        log.append({"i": i})
    # No files in the temp dir from the disabled log.
    assert list(tmp_path.iterdir()) == []


def test_log_with_none_path_is_noop(tmp_path: Path) -> None:
    """Direct constructor with path=None — same as disabled()."""
    log = AuditLog(path=None)
    log.append({"x": 1})
    assert list(tmp_path.iterdir()) == []


def test_concurrent_appends_produce_valid_jsonl(tmp_path: Path) -> None:
    """100 threads × 10 appends each → 1000 lines, every line valid
    JSON, no interleaving. Lock serialises writes."""
    p = tmp_path / "concurrent.jsonl"
    log = AuditLog(p)

    def writer(tid: int) -> None:
        for i in range(10):
            log.append({"tid": tid, "i": i})

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = p.read_text().splitlines()
    assert len(lines) == 1000
    for line in lines:
        # Each line must parse as a complete JSON object.
        rec = json.loads(line)
        assert "tid" in rec and "i" in rec and "ts" in rec


def test_append_preserves_extra_fields(tmp_path: Path) -> None:
    """The helper does not strip caller-provided fields; whatever
    the caller passes ends up in the record verbatim (plus ts)."""
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append({
        "stage": "step3.synth",
        "candidate_id": "EP-001",
        "function": "ssh_packet_socket_callback",
        "ir_id": "IR-001",
        "sink_count": 1,
        "elapsed_sec": 234.5,
        "supporting_substrate_edges": ["x", "y"],
    })
    rec = json.loads(p.read_text())
    assert rec["stage"] == "step3.synth"
    assert rec["sink_count"] == 1
    assert rec["supporting_substrate_edges"] == ["x", "y"]
    assert "ts" in rec


def test_default_audit_path_derives_from_out(tmp_path: Path) -> None:
    out = tmp_path / "foo" / "entrypoints.json"
    ap = default_audit_path(out, "step2")
    assert ap == tmp_path / "foo" / "step2_audit.jsonl"


def test_unicode_safe(tmp_path: Path) -> None:
    """Non-ASCII strings should round-trip cleanly (ensure_ascii=False)."""
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append({"note": "한글 테스트", "emoji_skipped": "ok"})
    rec = json.loads(p.read_text())
    assert rec["note"] == "한글 테스트"
