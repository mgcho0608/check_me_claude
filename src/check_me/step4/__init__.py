"""Step 4 — LLM Attack Scenario synthesis.

Per PLAN §4: Step 4 weaves Step 3's Evidence IRs (lines) into
attack scenarios (shapes). A scenario's ``exploit_chain.steps[]``
cites IR ids; each scenario must include at least one
``sink``. Chains may be single-IR or multi-IR — the latter is
the canonical case when an IR ends at an indirect-dispatch
boundary and a sibling IR rooted at the dispatch target picks
up the chain (e.g. CVE-2018-10933:
``ssh_packet_socket_callback`` → ... → ``ssh_packet_process``
boundary, then ``ssh_packet_process`` → ``ssh_packet_userauth_success``
sink).

Architecture:

  1. Load Step 3 ``evidence_irs.json`` and (optionally)
     supporting substrate / source for the IRs that carry a sink.
  2. Single LLM call (or chunked, if IR count is very large):
     given the full IR list and the sink-bearing IRs' source
     excerpts, the LLM emits one scenario per coherent chain it
     identifies. Schema:
     ``schemas/attack_scenarios.v1.json``.
  3. Resilience: per-scenario fallback is unnecessary at this
     layer — a single LLM call either returns a list or raises;
     the runner wraps the call with the same retry pattern as
     Step 3 (synth retry passes with quota cooldown).

The LLM's job is *synthesis*, not retrieval — Step 3 already did
the substrate walks. The LLM reads IRs and weaves them per the
schema's structural constraints.
"""

__all__: list[str] = []
