"""Step 1 — deterministic substrate extraction (Clang AST + static rules).

Per PLAN.md §3 / §5 Stage 0: no LLM in this step. The promise is
"same input -> same output", not "100% correct".

Output is a JSON object validated against schemas/substrate.v1.json with
seven categories: call_graph, data_control_flow, guards, trust_boundaries,
config_mode_command_triggers, callback_registrations, evidence_anchors.

Each category lives in its own module (call_graph.py, ...). The runner
coordinates AST index loading once per file and dispatches to the
per-category extractors.
"""
