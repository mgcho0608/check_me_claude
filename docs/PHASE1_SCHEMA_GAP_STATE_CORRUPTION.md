# Phase 1 — Schema Gap Analysis for State-Corruption / Lifecycle Vulnerabilities

This document captures the result of trying to label state-corruption / verify-
before-commit / persistent-state-then-execute style vulnerabilities using the
*current* `evidence_irs.v1.json` and `attack_scenarios.v1.json` schemas. The
goal is to ground Phase 2 schema design in concrete observed gaps rather than
speculative abstraction.

Two cases were traced end-to-end:

1. **libssh CVE-2018-10933** — already in our gold (`auth_bypass`). On
   re-examination it is *exactly* the selector-driven dispatch + state-
   corruption + state-reuse-by-later-commands pattern. The current gold
   captures the chain in prose but the schema cannot mark the role of the
   selector, the durability of the state mutation, or the later state-read
   sites as first-class structural facts.
2. **mbedtls `ssl_load_session()`** — not currently labeled. The function
   exhibits a textbook verify-before-commit shape: `memcpy()` of the entire
   session struct precedes certificate parsing; the parent struct stays
   committed even if cert parsing fails. Practical exploit at this commit is
   gated by AEAD on the ticket transport, but the *pattern* is real and
   useful as a schema-design specimen.

Each case is presented in three layers:

  - **Code trace** — the actual call path with file:line anchors.
  - **Current-schema mapping** — what we *can* say in the v1 schemas today.
  - **Schema gap** — what we cannot say structurally, only in free text.

The bottom of the document collates the gaps into a Phase-2 design proposal.

---

## Case 1: libssh CVE-2018-10933 — server accepts USERAUTH_SUCCESS from client

### Code trace

```
Network (attacker)
    ↓  raw bytes, single packet, type byte = 52 = SSH2_MSG_USERAUTH_SUCCESS
ssh_packet_socket_callback                    src/packet.c:144     [trust boundary, callback]
    ↓  parses bytes → session->in_packet.type = 52
ssh_packet_parse_type                         src/packet.c:521-531 [parse → state]
    ↓
ssh_packet_socket_callback                    src/packet.c:350     [calls process]
    ↓
ssh_packet_process                            src/packet.c:440-466 [SELECTOR-DRIVEN DISPATCH]
    ↓  default_packet_handlers[52] (table at src/packet.c:90)
ssh_packet_userauth_success                   src/auth.c:277       [no role/state guard]
    ↓
session->auth.state    = SSH_AUTH_STATE_SUCCESS              src/auth.c:285  [DURABLE STATE WRITE]
session->session_state = SSH_SESSION_STATE_AUTHENTICATED     src/auth.c:286  [DURABLE STATE WRITE]
session->flags        |= SSH_SESSION_FLAG_AUTHENTICATED      src/auth.c:287  [DURABLE STATE WRITE]
    ↓  ... later, on a separate inbound packet path ...
ssh_message_channel_request_open_reply_*      src/server.c:524    [STATE READ — gating]
    if ( session->flags & SSH_SESSION_FLAG_AUTHENTICATED )
        proceed with channel open
ssh_get_kex                                   src/kex.c:443       [STATE READ — gating]
    if ( session->session_state == SSH_SESSION_STATE_AUTHENTICATED )
        permit re-key
... and other gates in src/wrapper.c:506,521 ...
```

### Current-schema mapping

The existing `evidence_irs.json` for this CVE has a single IR-001 with one
8-node path: entry (callback) → intermediate (parse) → intermediate
(dispatch) → intermediate (handler entry) → sink (state write at
src/auth.c:286).

`attack_scenarios.json` has one AS-001 whose `exploit_chain.steps` walk
IR-001 four times, with step 4 describing the later state-read sites
*entirely in free text* (the prose mentions src/server.c:524, src/wrapper.c
:506/521, src/kex.c:443 but no schema field structures the relationship).

`sink_type` is set to `auth_bypass`, which is the closest enum value
available. `impact.category` is `privilege_bypass`.

### Schema gap

| Want to express | Current best | Lossy because |
|---|---|---|
| The dispatch at `ssh_packet_process` is selector-driven by an attacker-controlled byte | `path.nodes[…].role: "intermediate"` and `path.edges[…].kind: "callback"` | Doesn't mark *selector* nor *attacker controllability of selector*; downstream tooling can't distinguish "this dispatch is the attack hinge" from "this dispatch is internal control flow" |
| `session->session_state` and `session->flags` are *durable* attacker-corruptible state, not transient locals | `evidence_anchors[].note` free text | No structured "writes_resource(<resource>)" field; can't query "which IRs write this resource" |
| The bug is exploitable only because *later* code paths read this corrupted state without revalidation | `attack_scenarios.exploit_chain.steps[3].action` free text | Step 4 doesn't link to a separate "state-read IR"; the read sites src/server.c:524 etc. are not in any IR's `path.nodes`; cannot machine-trace "this consumer of the corrupted state" |
| Multi-IR weave: write-IR → read-IR with no revalidation between | `exploit_chain.steps[…].evidence_ir` (all 4 steps reference IR-001) | The read sites would belong to a separate IR-002 that doesn't exist; cannot express "IR-001 writes X, IR-002 reads X, no IR validates X between them" |
| The category-level fact "default_packet_handlers is a struct/array index dispatch where the index is attacker-controlled" | `evidence_anchors[3].note` (`"default_packet_handlers[52] = ssh_packet_userauth_success — the static table entry"`) | Step 1 substrate's `callback_registrations` row exists for this entry, but the *dispatch* via attacker-byte index is not marked anywhere structurally |

---

## Case 2: mbedtls `ssl_load_session()` — verify-before-commit

### Code trace

```
mbedtls_ssl_ticket_parse                      library/ssl_ticket.c:383
    ↓  validates ticket length, decrypts, AEAD-authenticates the ticket bytes
    ↓  (mbedtls_cipher_auth_decrypt at line 432 — this is the only attacker
    ↓   gate on ticket content; if AEAD passes, the decrypted bytes are
    ↓   trusted by the rest of the function)
ssl_load_session                              library/ssl_ticket.c:213
    ↓
memcpy( session, p, sizeof( mbedtls_ssl_session ) )                 line 225  [DURABLE STATE WRITE — full struct commit]
    ↓
if (cert_len == 0)
    session->peer_cert = NULL                                        line 237
else {
    session->peer_cert = mbedtls_calloc(...)                         line 246
    if ( mbedtls_x509_crt_parse_der(session->peer_cert, p, cert_len) != 0 ) {
        mbedtls_x509_crt_free( session->peer_cert )                  line 256  [PARTIAL ROLLBACK — only peer_cert]
        mbedtls_free( session->peer_cert )                           line 257
        session->peer_cert = NULL                                    line 258
        return ret                                                   line 259  [CALLER receives error code BUT *session has stale post-memcpy state*]
    }
}
```

The struct `mbedtls_ssl_session` includes:
  - `start` (timestamp)
  - `ciphersuite`, `compression`, `id_len`, `id[]`, `master[48]`
  - `peer_cert` (now nulled on cert-fail path)
  - `verify_result`, `ticket_lifetime`, `mfl_code`, `trunc_hmac`,
    `encrypt_then_mac`

If the caller ignores the return value (or uses the partial session), every
field except `peer_cert` is post-memcpy attacker-controlled bytes (gated by
AEAD).

The single caller at the same commit is `mbedtls_ssl_ticket_parse` itself
(line 448), which DOES propagate the error code. So at this commit the bug
is contained — but the *code-quality* defect (struct-commit-before-cert-
validate) is real and the pattern is what we want to be able to label.

### Current-schema mapping

The current schema would express this as a single IR with sink at
`ssl_load_session` line 225 (the memcpy). The cert-validation failure path
would appear as either an evidence anchor (`note: "rollback only nulls
peer_cert; rest of session struct stays committed"`) or as
`conditions.blocking[]` (`"caller ignores the returned error code"`).

`sink_type` choice is awkward:
  - `memory_write`? Technically yes — the memcpy IS a memory write. But
    that elides the lifecycle pattern (commit-before-validate-rollback-
    incomplete) which is the whole point.
  - `state_corruption`? Closer in spirit — but the current enum value
    description in `schemas/attack_scenarios.v1.json` is general and
    doesn't mark "partial rollback / commit-before-validate".

### Schema gap

| Want to express | Current best | Lossy because |
|---|---|---|
| The memcpy at line 225 is a *commit* of attacker-controlled bytes into a long-lived structure | `path.nodes[].role: "sink"` + `sink_type: "state_corruption"` | Does not name the *resource* (mbedtls_ssl_session struct) being committed; cannot link to a downstream IR that *uses* that struct after the failed validation |
| Cert validation at line 253 is the *should-have-been-pre-commit* step that runs *post-commit* | No field for "validation event"; would have to put in `evidence_anchors[].note` | No `validates_resource(<resource>)` effect type; cannot express "this validation, if it had run earlier, would have prevented the commit" |
| The rollback at lines 256-258 is *partial* (peer_cert nulled but parent struct stays) | Same — `evidence_anchors[].note` free text | No `missing_rollback(<resource>)` effect; cannot machine-detect "rollback covered some but not all fields touched by the prior commit" |
| The failure mode is "a bug *somewhere else* that ignores ssl_load_session's return value" | `conditions.blocking[]` text | The blocking condition references a hypothetical buggy caller, but no schema field links to *which* function or pattern would constitute that bug |

---

## Synthesis: gaps the v1 schemas cannot express structurally

Both cases share a common shortfall pattern. The gaps fall into four
buckets:

### Gap A — Selector-driven dispatch is not first-class

libssh's `ssh_packet_process` walks `default_packet_handlers[wire_byte]`
where `wire_byte` is attacker-controlled. The current schema marks the call
edge but not the "this is a selector dispatch and the selector is
attacker-controlled" property. As a result Step 2's pool ignores the
*targets* of such dispatches as candidates unless they happen to be
explicitly registered as callbacks (in libssh's case they are, via the
static table — but in projects where the table is built up dynamically
they would be missed).

### Gap B — Resource lifecycle is not first-class

Both cases mutate a *named long-lived resource* (libssh's session.flags;
mbedtls's session struct). The current schema treats these mutations as
generic memory writes (sink_type=memory_write or state_corruption) without
naming the resource. This means downstream tooling cannot:
  - Group IRs by which resource they touch
  - Express "IR-A writes resource X; IR-B reads resource X; no validation
    between"
  - Detect missing-rollback patterns by checking whether a write-IR's
    error path covers all the fields the success path touched

### Gap C — Multi-IR weave is implicit, not structured

Both cases want to weave at least two IRs:
  - libssh: IR-A (write the AUTHENTICATED state) + IR-B (read the
    AUTHENTICATED state in a later request handler)
  - mbedtls: IR-A (commit session struct) + IR-B (downstream code that
    reads the half-validated session)

The current `attack_scenarios.exploit_chain.steps[].evidence_ir` field
allows multi-IR references but the *semantics* of how those IRs connect
(write→read on shared resource, missing intermediate validation, etc.) is
prose only. Step 4's LLM has to infer the connection from text rather than
walk a structured edge.

### Gap D — Validation events have no first-class status

Both cases are about validation that happens in the wrong order or covers
the wrong scope. The current schema can mark a `guard` with a
`guard_call`, but only in the substrate-level taxonomy (Step 1 output);
there is no IR-level "validation_site" that downstream tooling can match
against write/read effects to reason about whether the validation properly
gates the use.

---

## Phase 2 design seeds (informed by these gaps)

These are seeds, not commitments. Each should be re-examined when more
state-corruption cases are labeled (e.g. lwip TIME-WAIT TOCTOU, or a
firmware update CVE if added to corpus).

### Seed S1 — Add `selector_dispatch` substrate category (Step 1)

```
selector_dispatches: [
  {
    "function": "ssh_packet_process",
    "file": "src/packet.c",
    "line": 463,
    "selector_source": "session->in_packet.type",
    "selector_origin": "external_io",   # network bytes
    "dispatch_table": "default_packet_handlers",
    "dispatch_kind": "indexed_array",   # vs "switch_case" vs "if_chain"
    "targets": ["ssh_packet_userauth_success", "ssh_packet_kexinit", ...]
  }
]
```

Step 2 gains a "callees of selector_dispatches whose selector_origin is
external_io" cut → adds dispatch targets to candidate pool.

Project-agnostic: pure AST/CFG pattern. Recognition: `function-call expr
inside switch/if-chain whose discriminator is a function parameter or a
field reachable from one`. Drives existing libssh CVE-2018-10933 + future
firmware-update-style CVEs.

### Seed S2 — Add optional `effects` field to evidence IRs

```
evidence_irs[].effects: [
  {
    "kind": "writes_resource" | "reads_resource" | "validates_resource"
          | "invalidates_resource" | "missing_rollback"
          | "missing_revalidation",
    "resource": "session.flags.SSH_SESSION_FLAG_AUTHENTICATED",
    "file": "src/auth.c",
    "line": 287,
    "note": "..."
  }
]
```

`resource` is a *normalized identifier* derived from the substrate's
data_control_flow rows — e.g. `<typename>.<field>` or `<callee>(<keyarg>)`.
The normalization rule itself is project-agnostic (string from substrate,
no special-cased names).

### Seed S3 — Add `axis: "resource"` to Step 3 retrieval

In addition to the current N=2 hybrid (call edges + shared global state),
add a third axis: functions that touch the *same normalized resource*
become BFS neighbors. This recovers IR pairs like the libssh write/read on
session.flags even when they live in unrelated files.

### Seed S4 — Allow exploit_chain edges to declare the weave semantic

```
attack_scenarios.exploit_chain.weaves: [
  {
    "kind": "write_then_use_without_revalidation",
    "writer_ir": "IR-001",
    "writer_effect_index": 0,        # index into IR-001.effects
    "reader_ir": "IR-002",
    "reader_effect_index": 0,
    "missing_validation_between": true
  }
]
```

This is the Step 4 first-class effect-weaving the user-AI suggestion
described. Alongside the existing `steps[]` (which stays for narrative
order), `weaves[]` makes the structural connections machine-readable.

---

## What this analysis does NOT yet establish

  - Whether seeds S1-S4 cover the lwip TIME-WAIT TOCTOU case (separate
    deeper trace needed)
  - Whether selector_dispatch_kind enum should distinguish
    indexed_array / switch_case / if_chain or be a single value
  - The exact normalization rule for `resource` (proposal: walk
    data_control_flow's def_use rows; first-class identifier = the
    longest common-prefix qualified name across mutating call sites — but
    this is a Phase-2 design decision, not a Phase-1 finding)
  - The serialization order between `evidence_irs[].effects` and existing
    `path.nodes` (do effects subsume sink-role nodes? probably not —
    effects describe *what*, role describes *where in the chain*)

These are explicit Phase-2 open questions; recording them here so they
don't get lost when the moment to design the schema arrives.

---

## What we *can* do now without schema changes

Even before the v2 schema work, two practical extensions to the existing
gold are possible *today* and would themselves serve as design input:

  1. **libssh** — add a second IR (IR-002) whose `path.nodes` walk one or
     two of the state-read sites (e.g. src/server.c:524, src/wrapper.c
     :521) so the read leg of the chain is in the gold. Then add a second
     step block to AS-001 that references IR-002 explicitly. This makes
     the multi-IR weave structural rather than prose-only, even within v1
     schema. (Cost: ~1-2 hours of careful labeling.)

  2. **mbedtls** — add an AS-002 to the existing gold, anchored on
     `ssl_load_session`, with a synthetic "if a caller mishandled the
     return value..." conditions.blocking note. This documents the
     *pattern* in our corpus even though the practical exploit is gated by
     AEAD at this commit. (Cost: ~1-2 hours.)

Both extensions ground the schema design in concrete in-corpus examples
without requiring new datasets and without committing to any schema
change.

---

## Recommended next step

If we proceed with Phase 1 corpus extension (which the user agreed to in
the prior turn), do the two no-schema-change extensions above first
(libssh IR-002, mbedtls AS-002). They:
  - cost roughly half a day of work each,
  - produce concrete labeled examples of the "want to express" rows in
    each gap table above,
  - validate that even within v1 we can push some way toward the
    state-corruption class without the schema burden,
  - give Phase 2 schema-design the strongest possible grounding (real
    labeled rows where the v1 expression is awkward → exactly what the
    new fields should fix).

Phase 2 (schema v2 + selector_dispatch cut + effects layer + resource
axis + effect-weaving) follows after seeing how those v1 extensions feel
in practice.
