"""End-to-end tests for the Step 3 runner with stub LLM."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config
from check_me.step3 import runner as runner_mod


def _cfg():
    return Config(
        url="https://x.test/v1", key="k", model="m",
        temperature=0.0, max_tokens=4096,
    )


def _resp(obj) -> ChatResponse:
    s = json.dumps(obj)
    return ChatResponse(
        content=s, finish_reason="stop",
        prompt_tokens=10, completion_tokens=20, total_tokens=30,
        model="m", raw={"choices": [{"finish_reason": "stop", "message": {"content": s}}]},
    )


class _SeqChat:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, client, config, request: ChatRequest) -> ChatResponse:
        self.calls.append({"messages": list(request.messages)})
        if not self.responses:
            raise AssertionError("ran out of canned responses")
        return self.responses.pop(0)


def _ir_response(function="entry", file="f.c", line=10):
    return {
        "id": "IR-tmp",  # runner overwrites
        "entrypoint": {"function": function, "file": file, "line": line},
        "runtime_context": {
            "trigger_type": "callback",
            "trigger_ref": "synthesised",
            "config_flags": [],
        },
        "path": {
            "nodes": [
                {"function": function, "file": file, "line": line, "role": "entry"},
            ],
            "edges": [],
        },
        "conditions": {"required": [], "blocking": []},
        "evidence_anchors": [
            {"file": file, "line_start": line, "line_end": line, "note": "entry decl"},
        ],
        "confidence": "high",
        "uncertainty": "",
    }


def _setup_dataset(tmp_path: Path, *, n_kept: int = 2, n_quarantined: int = 1) -> dict[str, Path]:
    """Lay out a minimal dataset on disk: substrate + entrypoints +
    a tiny source tree. Returns the file paths the runner uses."""
    src = tmp_path / "source"
    src.mkdir(parents=True)
    (src / "f.c").write_text(textwrap.dedent("""\
        int helper(int x) { return x + 1; }
        int entry(int y) {
            return helper(y) * 2;
        }
        int quarantined_entry(int z) {
            return z;
        }
    """))

    substrate = {
        "schema_version": "v1",
        "project": "test_proj",
        "cve": "CVE-T",
        "categories": {
            "call_graph": [
                {"caller": "entry", "callee": "helper",
                 "file": "f.c", "line": 3, "kind": "direct"},
            ],
            "data_control_flow": [],
            "guards": [],
            "trust_boundaries": [],
            "config_mode_command_triggers": [],
            "callback_registrations": [],
            "evidence_anchors": [],
        },
    }
    sub_path = tmp_path / "substrate.json"
    sub_path.write_text(json.dumps(substrate))

    entries = []
    for i in range(n_kept):
        entries.append({
            "id": f"EP-{i+1:03d}",
            "function": "entry" if i == 0 else f"entry_{i}",
            "file": "f.c",
            "status": "kept",
            "trigger_type": "callback",
            "confidence": "high",
            "line": 2 if i == 0 else None,
        })
    for j in range(n_quarantined):
        entries.append({
            "id": f"EP-Q-{j+1:03d}",
            "function": "quarantined_entry",
            "file": "f.c",
            "status": "quarantined",
            "trigger_type": "unknown",
            "confidence": "low",
            "quarantine_reason": "speculative",
        })
    ep_doc = {
        "schema_version": "v1",
        "project": "test_proj",
        "cve": "CVE-T",
        "entrypoints": entries,
    }
    ep_path = tmp_path / "entrypoints.json"
    ep_path.write_text(json.dumps(ep_doc))

    return {"substrate": sub_path, "entrypoints": ep_path, "source": src}


def test_runner_emits_one_ir_per_kept_entrypoint(tmp_path):
    paths = _setup_dataset(tmp_path, n_kept=2, n_quarantined=1)
    seq = _SeqChat([_resp(_ir_response("entry")), _resp(_ir_response("entry_1"))])
    out, report = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(),
        client="stub",
        chat_fn=seq,
    )
    assert len(out["evidence_irs"]) == 2  # quarantined skipped by default
    assert report.entrypoints_total == 3
    assert report.entrypoints_used == 2


def test_runner_assigns_global_sequential_ids(tmp_path):
    paths = _setup_dataset(tmp_path, n_kept=3, n_quarantined=0)
    seq = _SeqChat([
        _resp(_ir_response("entry")),
        _resp(_ir_response("entry_1")),
        _resp(_ir_response("entry_2")),
    ])
    out, _ = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=seq,
    )
    ids = [ir["id"] for ir in out["evidence_irs"]]
    assert ids == ["IR-001", "IR-002", "IR-003"]


def test_runner_includes_quarantined_when_flag_set(tmp_path):
    paths = _setup_dataset(tmp_path, n_kept=1, n_quarantined=1)
    seq = _SeqChat([_resp(_ir_response("entry")),
                    _resp(_ir_response("quarantined_entry"))])
    out, _ = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=seq,
        include_quarantined=True,
    )
    funcs = {ir["entrypoint"]["function"] for ir in out["evidence_irs"]}
    assert funcs == {"entry", "quarantined_entry"}


def test_runner_synthesis_failure_yields_synthetic_ir(tmp_path):
    """A single IR-synthesis exception must NOT abort the run.
    The entrypoint gets a placeholder IR with confidence=low and
    the failure recorded in uncertainty (PLAN Rule 4: silent
    delete forbidden). Other entrypoints still produce real IRs."""
    paths = _setup_dataset(tmp_path, n_kept=2, n_quarantined=0)

    failed_first = {"count": 0}

    def flaky_chat(client, config, request: ChatRequest) -> ChatResponse:
        # Fail the first call (entrypoint EP-001 / "entry"), succeed
        # on the second. With retry_passes=0 the failed entrypoint
        # keeps the synthetic IR.
        first_call = failed_first["count"] == 0
        failed_first["count"] += 1
        if first_call:
            raise RuntimeError("simulated 429 retry budget exhausted")
        return _resp(_ir_response("entry_1"))

    out, report = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=flaky_chat,
        synth_retry_passes=0,  # disable retry for this test
        synth_retry_cooldown_sec=0,
    )
    assert len(out["evidence_irs"]) == 2
    # First IR is the synthetic placeholder.
    first = out["evidence_irs"][0]
    assert first["confidence"] == "low"
    assert "Step 3 LLM synthesis call failed" in first["uncertainty"]
    # Second IR is the real one.
    assert out["evidence_irs"][1]["confidence"] == "high"


def test_runner_retry_pass_recovers_transient_failure(tmp_path):
    """A failure on the first pass that succeeds on a retry pass
    yields a real IR (not the synthetic placeholder). The runner
    overwrites the synthetic with the recovered one."""
    paths = _setup_dataset(tmp_path, n_kept=1, n_quarantined=0)

    state = {"calls": 0}
    def flaky_chat(client, config, request: ChatRequest) -> ChatResponse:
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("simulated transient")
        return _resp(_ir_response("entry"))

    out, report = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=flaky_chat,
        synth_retry_passes=1,
        synth_retry_cooldown_sec=0,
    )
    ir = out["evidence_irs"][0]
    assert ir["confidence"] == "high"
    assert any(c.get("retry_pass") for c in report.synth_calls)


def test_runner_validates_against_evidence_irs_schema(tmp_path):
    """Round-trip the runner's output against
    schemas/evidence_irs.v1.json so the schema and the runner stay
    in sync."""
    import jsonschema
    schema_path = Path(__file__).parents[1] / "schemas" / "evidence_irs.v1.json"
    if not schema_path.is_file():
        pytest.skip("schemas/evidence_irs.v1.json not present")
    schema = json.loads(schema_path.read_text())

    paths = _setup_dataset(tmp_path, n_kept=1, n_quarantined=0)
    seq = _SeqChat([_resp(_ir_response("entry"))])
    out, _ = runner_mod.run(
        substrate_path=paths["substrate"],
        entrypoints_path=paths["entrypoints"],
        source_root=paths["source"],
        config=_cfg(), client="stub", chat_fn=seq,
    )
    jsonschema.validate(out, schema)
