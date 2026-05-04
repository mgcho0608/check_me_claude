# Stage 0, Slice 4 — callback_registrations extractor

Adds the 5th substrate category. Four registration mechanisms are
detected, each emitting rows under the schema's ``kind`` enum:

| ``kind`` | Detection rule |
|---|---|
| ``function_table`` | Top-level static array initialized with function names. Each function-typed slot becomes one row; NULL / non-function slots are skipped. |
| ``function_pointer_assignment`` | A ``BinaryOperator`` ``=`` whose RHS resolves to a ``FunctionDecl`` and whose LHS is of function-pointer type (raw or via typedef — `cursor.type.get_canonical()` is used to expand typedef'd function-pointer aliases like libssh's ``ssh_callback_data``). |
| ``signal_handler`` | A call to ``signal``/``bsd_signal``/``sysv_signal`` whose 2nd argument resolves to a ``FunctionDecl``. ``sigaction`` registrations are picked up by the function_pointer_assignment path (the handler is assigned into ``struct sigaction.sa_handler``). |
| ``constructor`` | A ``FunctionDecl`` whose ``__attribute__((...))`` includes ``constructor`` or ``destructor`` keywords. The note records which. |

## End-to-end metrics on the three datasets

| Dataset | callback_registrations hit/gold | extracted total |
|---|---:|---:|
| dnsmasq-CVE-2017-14491 | 0/2 | 1 |
| libssh-CVE-2018-10933 | **2/2 (100%)** | 46 |
| contiki-ng-CVE-2021-21281 | 0/1 | 35 |
| **Total** | **2/5 (40%)** | — |

Combined Slice 1+2+3+4:

| Category | hit/gold |
|---|---:|
| call_graph | 14/16 (87.5%) |
| data_control_flow | 10/12 (83.3%) |
| guards | 8/8 (100%) |
| trust_boundaries | 2/5 (40%) |
| callback_registrations | 2/5 (40%) |
| **Total** | **36/46 (78%)** |

## libssh's two critical hits — what Slice 4 unlocks

For the libssh CVE the new substrate rows directly close two gaps
that earlier slices flagged as "by design":

1. **`function_table: default_packet_handlers[]`** at
   `src/packet.c:90` — extractor reports `ssh_packet_userauth_success`
   as registered at slot index 52 of `default_packet_handlers`. This
   bridges Slice 1's call_graph miss `ssh_packet_process →
   ssh_packet_userauth_success` at `src/packet.c:463` (the indirect
   call): joining `call_graph.callee = "cb->callbacks[type - cb->start]"`
   with `callback_registrations[registration_site = "default_packet_handlers[]",
   slot 52]` reaches the resolved target.

2. **`function_pointer_assignment: session->socket_callbacks.data =
   ssh_packet_socket_callback`** at `src/packet.c:406` — bridges
   Slice 3's trust_boundary miss for `ssh_packet_socket_callback`
   (the function does not directly call `recv` but is *installed*
   under a network-socket callback slot, so it is a logical trust
   boundary). The reasoning step that combines this with the trust
   boundary the libssh socket layer holds is downstream Step 2.

Both joins are **deterministic substrate operations** (look up by
key, find the registration), not LLM reasoning. Slice 4 makes them
possible without changing the call_graph or trust_boundary
extractors.

## On the 3 callback_registrations non-hits

Examining each gold row that does not match:

1. **dnsmasq `receive_query` / `tcp_request` at `dnsmasq.c:1565` /
   `1709` — gold `kind: "function_table"`.** These are *direct calls
   from the main event loop*, not function-pointer registrations.
   The dataset notes already acknowledge this: the gold's
   ``callback_registrations`` row notes "Not a function-pointer
   registration in the traditional sense; receive_query is invoked
   directly from the dnsmasq main event loop." The label `kind:
   "function_table"` was used because no enum value precisely fit;
   per PLAN.md §4.6 #8 (`unknown` is always allowed and accompanied
   by free-text), `kind: "unknown"` would be the more honest label.
   **The extractor is being correct in not emitting these as
   function_table.**

2. **contiki-ng `eventhandler` at `tcpip.c:809` — gold `kind:
   "function_table"`.** Line 809 is `PROCESS_THREAD(tcpip_process,
   ev, data)`. This is a Contiki-NG protothread *declaration macro*
   that expands to a function definition; it does not register
   `eventhandler` through any function-pointer table. `eventhandler`
   is invoked by direct call from the protothread body at
   `tcpip.c:833`. Same situation as dnsmasq above: gold stretched
   the `function_table` label because no enum value fits. The
   extractor correctly does not emit it.

These three gold rows would be more honest as `kind: "unknown"`
with a free-text note describing the protothread / main-loop
dispatch. The dataset gold was authored with stretched labels;
the extractor is faithful. A follow-up would either (a) relax these
gold labels to `unknown` to bring gold and extractor into agreement,
or (b) extend the schema with a `direct_dispatch_site` enum value.

Per CLAUDE.md "primitive correctness lives in pytest, not gold
expansion", Slice 4's correctness is verified by the 21 pytest
tests below; the gold-side question is documented here for later
discussion.

## Pytest

| File | tests | status |
|---|---:|---|
| tests/test_step1_call_graph.py | 5 | passing |
| tests/test_step1_data_control_flow.py | 23 | passing |
| tests/test_step1_guards.py | 24 | passing |
| tests/test_step1_trust_boundaries.py | 23 | passing |
| tests/test_step1_callback_registrations.py | 21 | passing |
| **Total** | **96** | **all passing** |

`callback_registrations` tests cover: static array of function names
emits function_table; slot index recorded in note; NULL slots
skipped; tables in function bodies are NOT extracted (top-level
only); struct-field assignment of function name; global function-
pointer variable assignment; int-field assignment is NOT extracted;
local function-pointer variable assignment; compound assignment is
NOT extracted; initializer form is NOT extracted (boundary case
documented); `signal()` with function handler; `signal()` with
constant `SIG_IGN` is NOT extracted; non-signal calls are not signal
handlers; `__attribute__((constructor))`; `__attribute__((destructor))`
emits the same `kind: "constructor"` row with `note: "destructor"`;
unrelated attribute is NOT a constructor; multi-attribute keeps the
constructor row; a file with all four mechanisms emits all four;
in-project filter; output determinism; output schema validation.

## Stage 0 exit-criteria status (PLAN.md §5)

1. ☐ Regex-baseline edge-count comparison — deferred to Stage 0 closure (eventually closed by `out/STAGE0_REGEX_BASELINE_METRICS.md`).
2. ☐ All 7 substrate categories — **5/7** in this slice. Two
   remaining: config_mode_command_triggers, evidence_anchors.
3. ☑ file:line provenance.
4. ☑ Determinism.
