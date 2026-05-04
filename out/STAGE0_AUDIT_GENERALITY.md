# Stage 0 audit — generality + gold honesty

User concern: Check Me's substrate extractor must NOT have any
data-specific structure tuned to inflate gold-matching on the three
test datasets. Generality and intuitiveness are the core values.

This audit (a) inspects every Step 0 source file for hidden bias
toward our datasets, (b) re-checks every gold row for "stretched"
enum labels that force-fit a value the row does not actually
belong to, and (c) reports the final state of the substrate after
both kinds of correction.

---

## Part A: Step 0 implementation generality

### Search for hardcoded dataset names in code logic

```
$ grep -rnE 'contiki|libssh|dnsmasq|tcpip_input|ssh_packet|receive_query|CVE-2017|CVE-2018|CVE-2021' src/
```

All matches are in module-level docstrings or comments
(illustrative examples). Zero matches in code logic
(`if name == "ssh_..."`, `if project == "libssh"`, etc.).
The CLI's docstring uses the contiki-ng dataset as an example
invocation — that is documentation, not a runtime branch.

Verdict: **no hardcoded dataset names in code**.

### API_TABLE in `trust_boundaries.py`

```
$ python3 -c "from check_me.step1.trust_boundaries import API_TABLE; ..."
API_TABLE size: 52
POSIX/libc match: 52
Non-standard: (none)
```

All 52 entries are POSIX / standard-libc names (`recv`,
`recvmsg`, `accept`, `sendto`, `read`, `pread`, `fopen`,
`getline`, `pipe`, `mq_receive`, `getenv`, `ioctl`, …).
None are project-specific wrappers.

Verdict: **API_TABLE is generic POSIX/libc**.

### `_RESERVED_CALL_NAMES` in `regex_baseline.py`

All entries are pure C standard keywords / operators / type
qualifiers (`if`, `for`, `sizeof`, `__attribute__`, `void`,
`unsigned`, …). None are project-specific.

Verdict: **reserved-name list is C-standard**.

### Include-path heuristic in `ast_index.py`

```
INCLUDE_ROOT_NAMES = {"include", "inc", "headers"}
```

Universal C-project conventions. Was added in Slice 1 to handle
projects that put headers under `include/<projectname>/` (libssh,
OpenSSL, many CMake projects); the names themselves are not
libssh-specific.

Verdict: **generic include-root naming convention**.

### Skip-dir heuristic

```
skip_dirs = ("tests", "test", "examples", "doc", "docs", "build", ".git")
```

Universal directory names. Generic.

### `libclang` candidate paths

Linux distro paths (`/usr/lib/x86_64-linux-gnu/libclang-18.so.1`
and family). Generic; an environment variable
`CHECK_ME_LIBCLANG` overrides for non-default installs.

### **Bias found**: function-pointer-type heuristic in `callback_registrations.py`

The original suffix list was:

```python
suffixes = ("_t", "_cb", "_callback", "_handler", "_fn", "_data")
```

The `_data` suffix was added during Slice 4 to make
libssh's typedef `ssh_callback_data` match the
function-pointer-type heuristic. This is dataset-specific
bias — a typedef ending in `_data` is almost always **not** a
function pointer (`payload_data`, `user_data`, `byte_data`, …
are all common non-callback names).

The `_t` suffix is also too broad — `size_t`, `pid_t`,
`pthread_t`, `int32_t` are all non-callback typedefs that
share that suffix.

**Fix applied**: remove `_t` and `_data` from the suffix list.
The remaining suffixes (`_cb`, `_callback`, `_handler`, `_fn`)
are conventionally callback-flavoured names. Crucially,
`_lhs_is_callback_target` already calls
`cursor.type.get_canonical()` to expand typedefs to their raw
form, so `ssh_callback_data` is still resolved (the canonical
form contains `(*` and matches the primary syntactic check).
After the fix, libssh's critical `function_pointer_assignment`
row at `src/packet.c:406` is still extracted (verified by re-
running `step1` and grepping for the row) — generality and
correctness coexist.

```python
def _is_function_pointer_type(type_text: str) -> bool:
    t = type_text.strip()
    if "(*" in t:                 # primary: works after canonicalization
        return True
    if t.endswith("(*)"):
        return True
    callback_suffixes = ("_cb", "_callback", "_handler", "_fn")
    return any(t.endswith(s) for s in callback_suffixes)
```

The new docstring states the contract explicitly: "to be
project-agnostic, not to maximize gold match on any one
dataset".

---

## Part B: gold label-honesty pass

PLAN.md §4.6 #8 mandates `unknown` is always allowed and must
carry a free-text note. Where a gold row used a stretched enum
value to force-fit a poor match, the row is corrected to
`unknown` with explicit free-text. Each correction is recorded in
the dataset's `notes.md` audit log (round 2).

### contiki-ng (6 corrections)

- **A10**. `data_control_flow` row's `line_end=1900` covered
  multiple `if` constructs, not a single branch. Narrowed to
  `1857-1873` (the actual single-branch extent) + tighter
  summary.
- **A11**. UIP_TCP at `uip6.c:1416` was `kind=compile_flag` but
  line 1416 is `#if UIP_TCP` directive. Changed to `kind=ifdef`.
- **A12**. PROCESS_THREAD callback_registrations row was
  `kind=function_table` but a protothread declaration macro is
  not a function-pointer table. Changed to `kind=unknown` +
  free-text note describing the protothread machinery.
- **A13**. EP-003 `trigger_type=callback` for uip_process —
  reached by mixed flavours (event / application / internal),
  no single enum fits. Changed to `trigger_type=unknown` +
  free-text.
- **A14**. AS-001 / AS-002 `sink_type=memory_read` — sink line
  1846 is a write to `uip_len`, not a memory read; the OOB
  read is downstream. Changed to `sink_type=state_corruption`
  with `impact.description` rewritten to make the two-step
  relationship explicit.

### libssh (2 corrections)

- **L5**. `compile_flag at src/server.c:524` row removed.
  `server.c` has no `#if WITH_SERVER` directive (verified by
  grepping the file's preprocessor lines); the whole file is
  compiled into the libssh server build via the CMake-level
  WITH_SERVER option. Line 524 is regular C inside a function,
  not a build-config marker. The packet.c:84 ifdef row already
  records WITH_SERVER as a config trigger, so removing the
  stretched row loses no information.
- **L6**. EP-002 (ssh_packet_process) `trigger_type=callback`
  → `unknown`. ssh_packet_process is called directly from
  ssh_packet_socket_callback; it is not itself registered as a
  callback. Explained in free-text as "structural pivot".

### dnsmasq (3 corrections)

- **D4**. Both callback_registrations rows had
  `kind=function_table` but the dispatch is a direct call from
  the main event loop. The row's own note conceded "Not a
  function-pointer registration in the traditional sense."
  Changed both to `kind=unknown` with free-text.
- **D5**. cli_argument at `forward.c:1439` row — line 1439 is
  the `answer_request` call site, not the CLI parsing site. The
  parser lives in `src/option.c`. Changed to `kind=unknown`
  with free-text describing this as a deployment-config
  dependency.
- **D6**. Four evidence_anchors rows (statement-line writes
  inside function bodies) removed. `structural_artifact` is for
  top-level facts (struct / typedef / enum / global / alias
  macro), not per-statement writes. The same lines are already
  visible through `data_control_flow`'s def_use rows for
  `add_resource_record` (line range 1065-1170 covers them all).

---

## Part C: substrate gold-match after both kinds of correction

| Category | hit / gold | % |
|---|---:|---:|
| call_graph | 14/16 | 88% |
| data_control_flow | 10/12 | 83% |
| guards | 8/8 | **100%** |
| trust_boundaries | 2/5 | 40% |
| config_mode_command_triggers | 4/5 | 80% |
| callback_registrations | 2/5 | 40% |
| evidence_anchors | 7/7 | **100%** |
| **GRAND TOTAL** | **47/58** | **81%** |

Compared with the pre-audit numbers (47/63 = 75%):

- `evidence_anchors` 7/11 → 7/7. Four stretched-label rows
  were removed; evidence_anchors is now honestly 100% on what
  is actually structural in the gold.
- `config_mode_command_triggers` 4/6 → 4/5. The libssh
  compile_flag stretch was removed.
- All other category ratios are unchanged.

The improvement comes from **gold becoming honest**, not from
the extractor learning the test data. The 11 remaining misses
are by construction — the extractor is project-agnostic, and
the gold rows that the extractor cannot match are documented
per slice as either:

- by-design (logical-boundary semantics that exceed what an
  intra-procedural deterministic AST extractor can produce),
- downstream-bridgeable (callback_registrations join keys
  exist; Step 2 reasoning will resolve them),
- deferred (cli_argument / mode_switch / hardcoded_value /
  key_reference enum values not yet implemented).

## Pytest

157/157 passing — same as before the audit. The function-pointer-
type heuristic change is exercised by the existing
`callback_registrations` test suite and a libssh-style
struct-field-assigned-function test was already in place; both
pass with the tighter suffix list.

## Verdict

- **Step 0 implementation is project-agnostic.** The only
  dataset-specific bias found (`_data` and `_t` suffixes) was
  removed without regressing the libssh use case, because
  `cursor.type.get_canonical()` already covers typedef'd
  function pointers generically.
- **Gold is honest.** Where a row used a stretched enum value,
  it is now `kind=unknown` with explicit free-text per
  PLAN §4.6 #8, or removed entirely when the row was redundant
  with another category.
- **Gold-match metric reflects extractor capability**, not
  inflated by stretched labels. 47/58 = 81% is the accurate
  number; the 11 misses are documented per-slice as gaps the
  extractor (correctly) does not paper over.
