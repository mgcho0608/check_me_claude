"""Smoke tests for Step 1 Slice 1 (call_graph extractor).

These run libclang on small synthetic inputs (no external project
checkout required) so they stay fast in CI. End-to-end validation
against the dataset gold files is performed by the runner script,
not pytest.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir()
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _edges(substrate: dict) -> list[dict]:
    return substrate["categories"]["call_graph"]


def test_direct_call_resolves_to_callee_name(tmp_path):
    root = _project(
        tmp_path,
        {
            "main.c": """\
                int helper(int x) { return x + 1; }
                int caller(int x) { return helper(x); }
            """,
        },
    )
    substrate, report = step1_runner.run(
        root, project_name="t", cve="CVE-test"
    )
    edges = _edges(substrate)
    assert any(
        e["caller"] == "caller"
        and e["callee"] == "helper"
        and e["kind"] == "direct"
        for e in edges
    ), edges
    assert report.parse_errors == 0


def test_indirect_call_through_function_pointer(tmp_path):
    root = _project(
        tmp_path,
        {
            "main.c": """\
                typedef int (*op_t)(int);
                int add1(int x) { return x + 1; }
                int dispatch(op_t op, int x) { return op(x); }
                int driver(int x) { return dispatch(add1, x); }
            """,
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    edges = _edges(substrate)
    indirect = [e for e in edges if e["kind"] == "indirect"]
    assert any(e["caller"] == "dispatch" for e in indirect), edges
    # And the registration-style direct calls should still be present.
    assert any(
        e["caller"] == "driver"
        and e["callee"] == "dispatch"
        and e["kind"] == "direct"
        for e in edges
    ), edges


def test_caller_attributed_to_enclosing_function(tmp_path):
    """A CallExpr deep inside nested if/for/switch must report the enclosing
    FunctionDecl, not '<file-scope>'. This was the root cause of the very
    first end-to-end miss against the dnsmasq gold."""
    root = _project(
        tmp_path,
        {
            "deep.c": """\
                int log_msg(const char *m) { return 0; }
                int run(int n) {
                    for (int i = 0; i < n; i++) {
                        if (i % 2) {
                            switch (i) {
                                case 1: log_msg("one"); break;
                                default: log_msg("other"); break;
                            }
                        }
                    }
                    return 0;
                }
            """,
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    edges = _edges(substrate)
    log_edges = [e for e in edges if e["callee"] == "log_msg"]
    assert log_edges, "expected at least one log_msg call edge"
    for e in log_edges:
        assert e["caller"] == "run", (
            f"caller should be 'run', got {e['caller']!r}"
        )


def test_runs_without_compile_commands_json(tmp_path):
    """The fallback include-dir heuristic alone is enough for trivial
    projects."""
    root = _project(
        tmp_path,
        {
            "include/proj/api.h": """\
                int api_call(int);
            """,
            "src/main.c": """\
                #include "proj/api.h"
                int api_call(int x) { return x * 2; }
                int main(void) { return api_call(3); }
            """,
        },
    )
    substrate, report = step1_runner.run(
        root, project_name="t", cve="CVE-test"
    )
    edges = _edges(substrate)
    assert any(
        e["caller"] == "main" and e["callee"] == "api_call" for e in edges
    ), edges
    assert report.parse_errors == 0


def test_substrate_validates_against_v1_schema(tmp_path):
    """Even with only call_graph populated, the output must conform to
    schemas/substrate.v1.json so downstream consumers can rely on the
    shape from day one."""
    schema_path = (
        Path(__file__).parents[1] / "schemas" / "substrate.v1.json"
    )
    if not schema_path.is_file():
        pytest.skip("schema file not present")
    schema = json.loads(schema_path.read_text())

    root = _project(
        tmp_path,
        {"f.c": "int g(void){return 0;} int f(void){return g();}"},
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")

    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)
