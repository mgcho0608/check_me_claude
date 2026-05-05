"""Step 4 end-to-end runner.

Loads ``evidence_irs.json`` (Step 3 output) and the project
source. For each IR that contains a ``sink`` role node, extracts
the source-code excerpt around the sink line (so the LLM can
verify the sink_type). Then issues a single LLM synthesis call
that emits the full ``attack_scenarios.v1.json`` document.

Resilience mirrors Step 3's runner: on raised synthesis
exception, the runner records a synthetic empty-scenarios
output with the failure reason in ``verdict.reason``, and
performs up to ``synth_retry_passes=2`` sequential retry passes
with a 60s cool-down between (so per-minute provider quotas can
refill).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..llm.client import ChatRequest, ChatResponse, chat, make_client
from ..llm.config import Config, StepKind, load_config
from . import synth as synth_mod

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "v1"


# Lines of source on each side of a sink-bearing line. The Step 4
# LLM uses this excerpt to verify the harmful operation lives
# where the IR claims and to pick the right sink_type. Shorter
# than Step 3's full-function excerpt because Step 4 needs only
# the immediate context of the sink line.
DEFAULT_SINK_CONTEXT_LINES = 30


@dataclass
class Step4Report:
    project: str
    cve: str
    irs_total: int
    irs_with_sinks: int
    scenarios_produced: int
    synth_call: dict[str, Any] = field(default_factory=dict)
    elapsed_sec: float = 0.0


def _read_source_excerpt(
    source_root: Path,
    file: str,
    line_start: int,
    line_end: int | None = None,
    *,
    context_lines: int = DEFAULT_SINK_CONTEXT_LINES,
) -> str:
    """Return ``±context_lines`` around ``[line_start, line_end]``
    of ``file`` (relative to ``source_root``). Best-effort: returns
    an empty string if the file is missing or unreadable. Project-
    agnostic: just file-line slicing."""
    abs_path = source_root / file
    if not abs_path.is_file():
        return ""
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    end = line_end if (line_end and line_end > line_start) else line_start
    a = max(1, line_start - context_lines)
    b = min(len(lines), end + context_lines)
    excerpt = "".join(
        f"{i:5d}: {lines[i-1]}" for i in range(a, b + 1)
        if 1 <= i <= len(lines)
    )
    header = f"[{file}:{a}-{b}]\n"
    return header + excerpt


def _collect_sink_excerpts(
    irs: list[dict[str, Any]],
    source_root: Path,
    *,
    context_lines: int = DEFAULT_SINK_CONTEXT_LINES,
) -> dict[str, str]:
    """For each IR that has at least one node with ``role: sink``,
    return ``{ir_id: concatenated source excerpt}``."""
    out: dict[str, str] = {}
    for ir in irs:
        ir_id = ir.get("id")
        if not isinstance(ir_id, str):
            continue
        sinks = [
            n for n in (ir.get("path", {}).get("nodes") or [])
            if n.get("role") == "sink"
        ]
        if not sinks:
            continue
        chunks: list[str] = []
        for s in sinks:
            file = s.get("file")
            line = s.get("line")
            if not isinstance(file, str) or not isinstance(line, int):
                continue
            ex = _read_source_excerpt(
                source_root, file, line, line_end=line,
                context_lines=context_lines,
            )
            if ex:
                chunks.append(ex)
        if chunks:
            out[ir_id] = "\n".join(chunks)
    return out


def run(
    *,
    evidence_irs_path: Path,
    source_root: Path,
    out_path: Path | None = None,
    config: Config | None = None,
    client: Any | None = None,
    sink_context_lines: int = DEFAULT_SINK_CONTEXT_LINES,
    synth_retry_passes: int = 2,
    synth_retry_cooldown_sec: float = 60.0,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> tuple[dict[str, Any], Step4Report]:
    """Run Step 4 end-to-end on a single dataset's Step 3 output.

    Returns ``(attack_scenarios_json, report)``. Writes the
    output to ``out_path`` if supplied. The shape matches
    ``schemas/attack_scenarios.v1.json``.
    """
    start = time.monotonic()

    irs_doc = json.loads(Path(evidence_irs_path).read_text())
    project = irs_doc.get("project", "<unknown>")
    cve = irs_doc.get("cve", "<unknown>")
    irs: list[dict[str, Any]] = irs_doc.get("evidence_irs", [])

    sink_excerpts = _collect_sink_excerpts(
        irs, Path(source_root), context_lines=sink_context_lines,
    )
    logger.info(
        "step4: project=%s cve=%s — %d IRs (%d with sinks)",
        project, cve, len(irs), len(sink_excerpts),
    )

    if config is None:
        config = load_config(step=StepKind.STEP4)
    if client is None:
        client = make_client(config)

    def _attempt_synthesis() -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            result = synth_mod.synthesise_scenarios(
                client=client, config=config,
                evidence_irs=irs, sink_excerpts=sink_excerpts,
                project=project, cve=cve,
                chat_fn=chat_fn,
            )
            scenarios = result.parsed.get("attack_scenarios", [])
            return scenarios, {"ok": True, "attempts": result.attempts}
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            logger.warning("step4: synthesis call failed — %s", err[:200])
            return [], {"ok": False, "error": err[:300]}

    scenarios, info = _attempt_synthesis()

    # Retry passes — sequentially re-attempt on failure with cooldown.
    for retry_pass in range(1, synth_retry_passes + 1):
        if info.get("ok"):
            break
        logger.info(
            "step4: retry pass %d/%d — sleeping %.0fs",
            retry_pass, synth_retry_passes, synth_retry_cooldown_sec,
        )
        if synth_retry_cooldown_sec > 0:
            time.sleep(synth_retry_cooldown_sec)
        scenarios, new_info = _attempt_synthesis()
        info = {**new_info, "retry_pass": retry_pass}

    # Renumber ids globally for stability.
    for i, sc in enumerate(scenarios, 1):
        sc["id"] = f"AS-{i:03d}"

    elapsed = time.monotonic() - start
    output = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "cve": cve,
        "attack_scenarios": scenarios,
    }
    if out_path is not None:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(output, indent=2) + "\n")

    report = Step4Report(
        project=project,
        cve=cve,
        irs_total=len(irs),
        irs_with_sinks=len(sink_excerpts),
        scenarios_produced=len(scenarios),
        synth_call=info,
        elapsed_sec=elapsed,
    )
    return output, report
