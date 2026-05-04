"""Step 2 — LLM entrypoint mining + verification.

Per PLAN.md §0 / §5 Stage 1:

- Miner (Proposer) reads Step 1 substrate and proposes runtime
  entrypoint candidates with reachability + attacker-controllability
  reasoning.
- Verifier — a separate fresh LLM session — independently critiques
  each candidate. The miner's reasoning is NOT shared with the
  verifier (anchoring prevention).
- Final output is ``entrypoints.v1.json`` matching the schema, with
  candidates split into ``kept`` and ``quarantined`` statuses.

The substrate is potentially huge (tens of thousands of rows for a
project the size of contiki-ng). ``substrate_slice`` distills it to
the candidate-relevant subset before either prompt sees it. This
slicing is project-agnostic — it relies only on substrate categories,
not on dataset names or known symbol patterns.
"""

from .substrate_slice import (
    SubstrateSlice,
    slice_for_candidate,
    slice_substrate,
)

__all__ = [
    "SubstrateSlice",
    "slice_for_candidate",
    "slice_substrate",
]
