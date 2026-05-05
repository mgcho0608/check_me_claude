"""Step 3 — LLM Evidence IR synthesis.

Per PLAN §3: each ``kept`` entrypoint from Step 2 is the start of an
execution-path Evidence IR. Step 3 connects points (entrypoints +
substrate facts) into lines (concrete execution paths with sinks,
guards, and data-flow edges) so Step 4 can weave lines into shapes
(attack scenarios).

Architecture:

  1. Deterministic retrieval (no LLM): for each kept entrypoint,
     compute the N=2 hybrid neighborhood — call-graph hops AND
     shared-global-state co-readers/writers. The output is a fixed
     set of ``(function, file)`` nodes plus the substrate edges
     among them. PLAN §3 explicitly forbids LLM free choice of
     code scope; the retrieval is a pure substrate walk.
  2. Source-code excerpt extraction: pull each function's body
     source from ``datasets/<key>/source/`` for inclusion in the
     LLM prompt. The IR's ``evidence_anchors`` cite line ranges
     from these excerpts.
  3. LLM synthesis (one call per entrypoint, temperature=0): the
     LLM produces an IR matching ``schemas/evidence_irs.v1.json``
     — nodes (with roles entry/guard/sink/intermediate), edges
     (call/dataflow/controlflow/callback/config/state), conditions
     (required + blocking), and evidence_anchors with file:line
     provenance.

The lossless rule from Step 2 carries forward: every ``kept``
entrypoint produces an IR. Quarantined entries are not consumed
by default (per CLAUDE.md "Step 3 default 입력은 status: kept 행"),
but the runner exposes an option to include them for audit/dip
passes.
"""

from .retrieval import (
    Neighborhood,
    NeighborhoodNode,
    NeighborhoodEdge,
    compute_neighborhood,
)

__all__ = [
    "Neighborhood",
    "NeighborhoodNode",
    "NeighborhoodEdge",
    "compute_neighborhood",
]
