# Stage 0, Slice 1 — call_graph extractor metrics

`python -m check_me step1 --src <project>/source --project <name> --cve <id> --out <out>/substrate.json`

| Dataset | files | parse_errors | edges_total | direct | indirect | gold edges | gold hits | hit-rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dnsmasq-CVE-2017-14491 | 38 | 6 | 4746 | 4742 | 4 | 5 | 5 | 5/5 (100%) |
| libssh-CVE-2018-10933 | 74 | 336 | 6517 | 6432 | 85 | 4 | 3 | 3/4 (75%) |
| contiki-ng-CVE-2021-21281 | 693 | 5830 | 15280 | 14028 | 1252 | 7 | 6 | 6/7 (86%) |

**Total: 14/16 gold edges hit (87.5%).**

## Notes on the two non-hits

Both are by design — they require capability that lives in later slices, not Slice 1.

### libssh: `ssh_packet_process → ssh_packet_userauth_success` at `src/packet.c:463` (gold `kind=indirect`)
The extractor reports the AST-truthful edge: `caller=ssh_packet_process, callee="cb->callbacks[type - cb->start]", kind=indirect`. The gold names the resolved target through libssh's `default_packet_handlers[]` static table at `src/packet.c:90`. **Resolving an indirect call site through a function-pointer table is the job of Slice 4 (callback_registrations)**; once that slice indexes static dispatch tables, this edge will be reported as `(ssh_packet_process, ssh_packet_userauth_success, indirect, via=default_packet_handlers[52])`.

### contiki-ng: `tcpip_process → eventhandler` at `os/net/ipv6/tcpip.c:833` (gold `caller=tcpip_process`)
The extractor reports `caller=process_thread_tcpip_process`. This is the actual symbol the `PROCESS_THREAD(tcpip_process, ev, data)` macro expands to. The gold uses the human-meaningful protothread name `tcpip_process` (documented in `notes.md` audit log A9 of that dataset). **Macro-expanded function naming is a known semantic gap** — Step 1 reports what the AST contains; downstream Step 2 reasoning will map `process_thread_<X>` back to `<X>` for protothreads. Auto-stripping the prefix in Slice 1 would be a contiki-ng-specific hack.

## Parse-error counts

`fatal:` and `error:` are now both counted (initial Slice 1 release counted only `error:` and undercounted libssh by 100%). High counts on contiki-ng (5830) reflect platform/board-specific headers (each TARGET=... build pulls in a different config); the call-graph extraction is robust enough that 6/7 gold edges still resolve. libssh's 336 errors come from CMake-generated headers that were not produced (no `cmake` configure run); a stub `config.h` injected via `--extra-arg=-I/tmp/libssh-stubs` recovered most of the substrate.

## What Slice 1 does NOT do (deferred to later slices)

(As actually executed in the closed Stage 0; the original plan in Slice 1 had Slice 3 as callback_registrations and Slice 4 as trust_boundaries. The final ordering, reflected here, swaps those two so that Slice 3 closes more quickly.)

- **Slice 2** — data/control flow extraction (def/use chains, conditional branches), guards (call + result-checking pairs).
- **Slice 3** — trust boundaries (network sockets, IPC, file reads).
- **Slice 4** — callback registrations (function-pointer tables, signal handlers, constructors); the substrate row that downstream layers can join with the Slice 1 indirect call edges to resolve their targets.
- **Slice 5** — config/mode/command triggers (`#ifdef`, CLI argument parsing, mode switches).
- **Slice 6** — evidence anchors (top-level structural artefacts, magic-value macros).

## Reproducing

```
pip install -e .
python3 -m check_me step1 \
  --src datasets/dnsmasq-CVE-2017-14491/source \
  --project dnsmasq --cve CVE-2017-14491 \
  --out out/dnsmasq-CVE-2017-14491/substrate.json

python3 -m check_me step1 \
  --src datasets/contiki-ng-CVE-2021-21281/source \
  --project contiki-ng --cve CVE-2021-21281 \
  --out out/contiki-ng-CVE-2021-21281/substrate.json

python3 -m check_me step1 \
  --src datasets/libssh-CVE-2018-10933/source \
  --project libssh --cve CVE-2018-10933 \
  --out out/libssh-CVE-2018-10933/substrate.json \
  --extra-arg=-I/tmp/libssh-stubs   # see source/build_commands in metadata.json
```

Pytest: `python3 -m pytest tests/`. 5/5 passing.

## Stage 0 exit-criteria status

Per PLAN.md §5 Stage 0:

1. ☐ Regex-baseline comparison — **deferred to Stage 0 closure**. Eventually closed by `out/STAGE0_REGEX_BASELINE_METRICS.md`, which also amends the criterion's wording (the headline is precision + indirect-edge coverage, not raw edge count).
2. ☐ "All 7 substrate categories extracted and output as validated JSON." — 1/7 categories implemented (call_graph). Six remaining slices.
3. ☑ "Output includes line numbers, file paths, function signatures for all facts." — file:line on every edge.
4. ☑ "Extraction is fully deterministic (same input → same output, no LLM variance)." — pure libclang AST traversal, no randomness.

> **Note:** This report is a Slice-1-time snapshot. For the post-audit gold-match numbers (47/58 = 81% across all 7 categories), see `out/STAGE0_AUDIT_GENERALITY.md`.
