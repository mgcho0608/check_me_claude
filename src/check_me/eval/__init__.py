"""Step 4 evaluation harness — gold vs pipeline output.

Per PLAN §5 Stage 3 / §4.4: each step's output is independently
evaluable. Step 1/2 results admit deterministic matching against
gold (function/file/enum equality on substrate rows and entrypoint
status). Step 3/4 results require LLM-judge matching for the
semantic equivalence question — "are these two IRs describing the
same execution path?" / "are these two scenarios describing the
same vulnerability?" — because LLM-synthesised paths can pick
different intermediate functions or different sink lines while
still capturing the same chain.

Module layout:

  step1_match.py   — substrate row coverage (call_graph,
                      trust_boundaries, callback_registrations,
                      guards, evidence_anchors,
                      config_mode_command_triggers,
                      data_control_flow)
  step2_match.py   — entrypoint coverage (function-name match;
                      kept/quarantined cross-tab vs gold)
  step3_match.py   — IR matching: deterministic node coverage
                      + LLM judge for chain equivalence
  step4_match.py   — scenario matching: deterministic enum
                      equality on sink / impact / verdict + LLM
                      judge for chain narrative equivalence
  judge.py         — shared LLM judge: ``judge_pair(gold, ours)``
                      → verdict {same, partial, different}
                      + reason text. Schema-validated output.
  runner.py        — orchestrate per-dataset, write
                      ``eval_report.json`` with per-step metrics
                      and overall pass/fail per PLAN exit
                      criteria (§5 Stage 3).

Project-agnostic: matchers walk schema-defined fields only; no
project-name branching. The LLM judge prompts cite only the
schema's enum vocabulary and never name a corpus.
"""

__all__: list[str] = []
