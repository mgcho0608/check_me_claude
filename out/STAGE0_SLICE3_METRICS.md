# Stage 0, Slice 3 — trust_boundaries extractor

Adds the fourth substrate category: `trust_boundaries`. A function
is a (syntactic) trust boundary if its body directly invokes one
of the curated POSIX / common-libc external-I/O APIs in
`step1/trust_boundaries.py::API_TABLE`. One row is emitted per
`(function, kind, direction)`; functions that exercise both
directions (e.g. an ``echo`` that calls both ``recv`` and ``send``)
get one row per direction.

## API coverage

The curated table covers four kinds:

- `network_socket`: recv / recvfrom / recvmsg / recvmmsg / accept /
  accept4 (untrusted_to_trusted), send / sendto / sendmsg / sendmmsg
  (trusted_to_untrusted), socket / bind / listen / connect /
  setsockopt / getsockopt (unknown direction).
- `file_read`: read / pread / readv / fread / fgets / fgetc /
  getline / getdelim (untrusted_to_trusted), write / pwrite / writev
  / fwrite / fputs / fputc (trusted_to_untrusted), open / openat /
  fopen / freopen / creat (unknown — open does not yet specify which
  direction the file will be used for).
- `ipc_endpoint`: mq_receive / msgrcv / shm_open
  (untrusted_to_trusted), mq_send / msgsnd (trusted_to_untrusted),
  pipe / pipe2 (unknown).
- `external_io`: getenv / secure_getenv / scanf-family
  (untrusted_to_trusted), ioctl / fcntl (unknown).

A pytest test (`test_api_table_directions_are_valid_enum`) asserts
every entry uses schema-valid `kind` and `direction` enum values.

## End-to-end metrics on the three datasets

| Dataset | trust_boundaries hit / gold | extracted total |
|---|---:|---:|
| dnsmasq-CVE-2017-14491 | 2/2 (100%) | 94 |
| libssh-CVE-2018-10933 | 0/1 (0%) | 50 |
| contiki-ng-CVE-2021-21281 | 0/2 (0%) | 53 |
| **Total** | **2/5 (40%)** | — |

Combined Slice 1+2+3:

| Category | hit/gold |
|---|---:|
| call_graph | 14/16 (87.5%) |
| data_control_flow | 10/12 (83.3%) |
| guards | 8/8 (100%) |
| trust_boundaries | 2/5 (40%) |
| **Total** | **34/41 (83%)** |

## Why the 3 trust_boundary misses are by design

All three gold rows that the extractor does not match are *logical*
trust boundaries — functions the codebase considers as the entry
point — that do not directly invoke an external-I/O API. The
attacker bytes reach them through callback installation:

- **libssh `ssh_packet_socket_callback`** (`src/packet.c:144`) is
  registered as `session->socket_callbacks.data` by
  `ssh_packet_register_socket_callback` (`src/packet.c:405-410`).
  The actual `recv` / `read` happens inside libssh's socket layer
  (`src/socket.c`), not in this function.
- **contiki-ng `tcpip_input`** (`os/net/ipv6/tcpip.c:445`) is the
  entry point that the lower 6LoWPAN / radio layer hands packets to.
  It posts a `PACKET_INPUT` event via `process_post_synch` rather
  than calling any I/O API.
- **contiki-ng `input`** (`os/net/ipv6/sicslowpan.c:1802`) is the
  6LoWPAN reassembly callback. It is reached via the radio driver's
  function table; no direct I/O call.

**The bridge is Slice 5 (callback_registrations).** Once the
substrate indexes function-pointer table installations and explicit
`__attribute__((constructor))` / signal-handler / event-callback
registrations, downstream Step 2 reasoning can recognize that
`ssh_packet_socket_callback` is installed *under* a socket callback,
making it a logical trust boundary even without a direct API call.
This is the same architectural gap that makes libssh's
`ssh_packet_process -> ssh_packet_userauth_success` indirect edge
unresolved in the call_graph — both effects bridged by Slice 5.

Per CLAUDE.md ("primitive correctness lives in pytest, not gold
expansion"), Slice 3's correctness is verified by 23 primitive
pytest tests, not by 100% gold coverage on logical boundaries.

## Pytest

| File | tests | status |
|---|---:|---|
| tests/test_step1_call_graph.py | 5 | passing |
| tests/test_step1_data_control_flow.py | 23 | passing |
| tests/test_step1_guards.py | 24 | passing |
| tests/test_step1_trust_boundaries.py | 23 | passing |
| **Total** | **75** | **all passing** |

`trust_boundaries` tests cover: each of the four kinds with its
intended direction (recv/recvmsg/accept → network input;
sendto → network output; read/fopen/fgets/write → file
in/out/unknown; pipe/msgrcv → IPC; getenv/scanf/ioctl →
external_io); a function exercising both recv AND send produces
two rows; internal functions (memcpy/strlen) are NOT marked as
trust boundaries; the boundary `line` is the function decl, not
the API call site; the `note` field includes the API name and call
site line; in-project filter; per-function attribution; output
determinism; output schema validation; and an enum-validity check
on every API_TABLE entry.

## Stage 0 exit-criteria status (PLAN.md §5)

1. ☐ Regex-baseline edge-count comparison — deferred to Slice 5.
2. ☐ All 7 substrate categories — **4/7** in this slice. Three
   remaining: callback_registrations, config_mode_command_triggers,
   evidence_anchors.
3. ☑ file:line provenance.
4. ☑ Determinism.
