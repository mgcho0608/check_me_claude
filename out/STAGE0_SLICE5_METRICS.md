# Stage 0, Slice 5 — config_mode_command_triggers extractor

Adds the 6th substrate category. Two mechanisms covered:

| ``kind`` | Detection rule |
|---|---|
| ``ifdef`` | Source-text scan of every ``.c`` and ``.h`` file under the project root for ``#if`` / ``#ifdef`` / ``#ifndef`` / ``#elif`` / ``#elifdef`` / ``#elifndef`` directives. Each identifier in the conditional remainder produces one row (so ``#if defined(A) || defined(B)`` emits two rows). The reserved word ``defined`` is filtered. Backslash-continued directives are joined; line and block comments are stripped from the remainder before identifier extraction. |
| ``compile_flag`` | ``-D<NAME>`` and ``-D<NAME>=<VALUE>`` flags from each TU's clang argument list (typically taken from ``compile_commands.json``). One row per ``(file, macro)`` with ``line: 0`` to signal "comes from build configuration, not from source". |

Two mechanisms in the schema enum (``cli_argument`` and
``mode_switch``) are out of scope for this slice — both require
either runtime-CLI recognition or heuristic naming, both of which
sit better in a later slice.

## End-to-end metrics on the three datasets

| Dataset | config_triggers hit/gold | extracted total |
|---|---:|---:|
| dnsmasq-CVE-2017-14491 | 1/2 (50%) | 812 |
| libssh-CVE-2018-10933 | 1/2 (50%) | 645 |
| contiki-ng-CVE-2021-21281 | 2/2 (100%) | 6 046 |
| **Total** | **4/6 (67%)** | — |

Combined Slice 1+2+3+4+5:

| Category | hit/gold |
|---|---:|
| call_graph | 14/16 (87.5%) |
| data_control_flow | 10/12 (83.3%) |
| guards | 8/8 (100%) |
| trust_boundaries | 2/5 (40%) |
| callback_registrations | 2/5 (40%) |
| config_mode_command_triggers | 4/6 (67%) |
| **Total** | **40/52 (77%)** |

## On the 2 config_triggers non-hits

Examining each:

1. **dnsmasq `cli_argument: --auth-zone / --local-zone` at
   `src/forward.c:1439`** — the gold row uses ``kind:
   "cli_argument"`` to record that the local-answer branch is gated
   on dnsmasq being configured with auth-zone / local-zone CLI
   options. **`cli_argument` is explicitly out of scope for this
   slice** (recognising arbitrary CLI parsing idioms is heuristic
   and brittle; deferred). Expected miss; extractor is honest in not
   pretending to detect it.

2. **libssh `compile_flag: WITH_SERVER at src/server.c:524`** — line
   524 is `if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED)`,
   regular C code inside a `#if WITH_SERVER` block. The gold row
   marks line 524 with `kind: "compile_flag"` to communicate "this
   line is reachable only when WITH_SERVER is set". The extractor's
   contract for `compile_flag` is "rows that come from build
   configuration, not from source", with `line: 0` as the signal.
   The extractor *does* emit `compile_flag` rows for ``WITH_SERVER``
   from the libssh stub args, and *does* emit `ifdef` rows for the
   `#if WITH_SERVER` directives in source. What it does not do is
   propagate the surrounding `#if` context onto every line inside
   the block. **The gold label is a stretched use of `compile_flag`
   to mean "code reachable only under flag X"; honest options are
   either to relax the gold to point at the directive line (an
   `ifdef` row) or to introduce a "compile-context" semantic on top
   of the substrate, which is downstream Step 2 reasoning.**

## Pytest

| File | tests | status |
|---|---:|---|
| tests/test_step1_call_graph.py | 5 | passing |
| tests/test_step1_data_control_flow.py | 23 | passing |
| tests/test_step1_guards.py | 24 | passing |
| tests/test_step1_trust_boundaries.py | 23 | passing |
| tests/test_step1_callback_registrations.py | 21 | passing |
| tests/test_step1_config_triggers.py | 19 | passing |
| **Total** | **115** | **all passing** |

`config_triggers` tests cover: bare `#ifdef` emits one row; `#ifndef`
recorded with directive in note; `#if defined(X)` extracts X;
multi-identifier `#if defined(A) || defined(B)` emits both;
`#elif defined(B)` extracted; ``defined`` is not itself emitted as
a name; ifdefs in header files extracted; multiple ifdefs in one
file each yield their own row (and repeated `#ifdef A` produces a
row per directive line); line / block comments stripped from
remainder; `#include` is not mistaken for `#if`; line numbers match
the directive; `-DENABLE_FOO` extracted; `-DBUFSIZE=1024` records
value in note; separate `-D NAME` (two args) handled; compile_flag
rows have `line: 0`; repeated `-DA` collapses to one row;
deterministic output; output schema validation.

## Stage 0 exit-criteria status (PLAN.md §5)

1. ☐ Regex-baseline edge-count comparison — deferred to Stage 0 closure (eventually closed by `out/STAGE0_REGEX_BASELINE_METRICS.md`).
2. ☐ All 7 substrate categories — **6/7** in this slice. One
   remaining: evidence_anchors.
3. ☑ file:line provenance.
4. ☑ Determinism.
