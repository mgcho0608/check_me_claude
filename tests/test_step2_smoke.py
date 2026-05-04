"""Live smoke test for Step 2 — opt-in via CHECK_ME_LIVE_LLM=1.

Issues real LLM calls. Skipped by default so offline ``pytest`` runs
free + fast. Run with::

    CHECK_ME_LIVE_LLM=1 pytest tests/test_step2_smoke.py -v

Uses a SMALL synthetic substrate slice — not one of the production
datasets — to keep token cost bounded (a single project-scale dataset
slice would burn ~100k input tokens). The point of this smoke test is
"the wiring works end-to-end against a real provider", not "the model
is good at finding entrypoints in real CVEs". The latter is the next
slice of work (cassette comparisons against the gold files).
"""

from __future__ import annotations

import json
import os

import pytest

from check_me.step2 import runner as runner_mod


_LIVE = os.environ.get("CHECK_ME_LIVE_LLM") == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="set CHECK_ME_LIVE_LLM=1 to run live-API Step 2 smoke",
)


def _tiny_substrate():
    """A minimal substrate with one obvious entrypoint and one
    obvious non-entrypoint so the live LLM has something concrete
    to mine + verify."""
    return {
        "schema_version": "v1",
        "project": "smoke_test_project",
        "cve": "CVE-SMOKE",
        "categories": {
            "call_graph": [
                {"caller": "handle_packet", "callee": "process_payload",
                 "file": "net.c", "line": 12, "kind": "direct"},
                {"caller": "internal_log", "callee": "format_string",
                 "file": "log.c", "line": 4, "kind": "direct"},
            ],
            "data_control_flow": [],
            "guards": [
                {"function": "handle_packet", "file": "net.c",
                 "guard_call": "len > 0", "guard_line": 7,
                 "result_used": True},
            ],
            "trust_boundaries": [
                {"kind": "network_socket", "function": "handle_packet",
                 "file": "net.c", "line": 5,
                 "direction": "untrusted_to_trusted",
                 "note": "calls recvmsg at net.c:6"},
            ],
            "config_mode_command_triggers": [],
            "callback_registrations": [],
            "evidence_anchors": [],
        },
    }


def test_step2_runs_end_to_end_against_real_provider():
    output, report = runner_mod.run(_tiny_substrate())

    # Envelope sanity.
    assert output["schema_version"] == "v1"
    assert output["project"] == "smoke_test_project"
    assert output["cve"] == "CVE-SMOKE"

    # Schema validation.
    import jsonschema
    from pathlib import Path
    schema_path = Path(__file__).parents[1] / "schemas" / "entrypoints.v1.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text())
        jsonschema.validate(output, schema)

    # Behavioural expectations:
    # - The miner should propose at least one candidate (handle_packet is
    #   the obvious one). We don't pin the exact count — different runs
    #   may surface different alternatives.
    assert report.candidates_proposed >= 1, (
        f"miner proposed nothing; report={report}"
    )

    # - The verifier should keep handle_packet (or quarantine it with
    #   a reason — both are acceptable so long as the verdict is
    #   present). We just check that every entrypoint has a status.
    for e in output["entrypoints"]:
        assert e["status"] in {"kept", "quarantined"}
        if e["status"] == "quarantined":
            assert "quarantine_reason" in e

    # - At least one candidate's function is handle_packet (the only
    #   trust-boundary function in the substrate). Anything else would
    #   be the LLM hallucinating.
    fns = {e["function"] for e in output["entrypoints"]}
    assert "handle_packet" in fns, fns
