# Check Me Plan

## Purpose of This Plan

This document is the architectural and migration plan for turning Check Me into a 4-step security analysis framework with deterministic substrate foundation and LLM-driven reasoning.

The role of this plan is to prevent drift.

It exists so that implementation work does **not** collapse into:

- benchmark-local hacks,
- profile-specific band-aids,
- LLM improvisation without structured substrate,
- exception-driven design,
- irreversible rewrites.

---

## 0. Non-Negotiable Project Direction

Check Me is moving toward:

> **4-step pipeline: rule-based substrate extraction → LLM entrypoint mining + verification → LLM execution-path Evidence IR → LLM exploit scenarios. Built and evaluated on project-level codebases grounded in authoritative sources.**

### Aegis Inspect Workflow

Step 1: 프로젝트의 정보를 구조화해서 substrate 구축
Step 2: LLM entrypoint candidate mining + verification
Step 3: LLM이 substrate + 코드 일부 → 실행 경로별 Evidence IR 그룹핑
Step 4: LLM이 Evidence IR + 코드 일부 → 공격 시나리오 도출
### Mental Model: Points → Lines → Shapes

step 1-4는 exploit 가능한 공격 시나리오라는 도형을 완성하는 과정.
도형은 선으로 이루어지고, 선은 점으로 이루어짐.
선의 중간 지점은 몰라도, 선의 시작 지점은 entry point만이 가능.

- Step 1은 선을 구성할 수 있는 점들을 찾는 과정 (정적 분석 + 휴리스틱)
- Step 1에서 룰-베이스로 찾기 힘든 runtime 기반 entry point들을 Step 2에서 추가하고 검증
- Step 3는 점들을 이어 선을 구성 (실행 path를 연결한 evidence IR)
- Step 4에서 그 선들을 엮어서 유의미한 도형 완성
- 도형은 선 하나로 이루어질 수도 있고, 같은 선을 여러 번 다른 순서로 쓸 수 있음

- **Step 1 (정적 Substrate 구축 — 점을 찾음):** 선을 구성할 수 있는 점들을 찾는 과정. 정적 분석 기반 rule-based extractor로 다음을 구축: call graph, data/control flow, guard/enforcement 관계, trust boundary, config/mode/command trigger, callback registration, evidence anchor. semantic 추론이 동반되는 항목(trust boundary, mode trigger 등)은 정적 룰 기반 휴리스틱으로 추출됨. substrate의 약속은 "ground truth"가 아니라 **동일 입력에 동일 출력이 보장되는, 추출 가능한 최선의 정적 정보**. 100% 정확하지 않을 수 있음을 downstream이 인지하고 동작. layer 출력은 단일 형태로 통일됨 (fact / heuristic이 형식적으로 나뉘지 않음).
- **Step 2 (LLM Entrypoint Mining — 선의 시작 점을 추가):** 선의 중간 지점은 몰라도 선의 시작 지점은 entry point만이 가능. Step 1에서 룰-베이스로 찾기 힘든 runtime 기반 entry point 들을 Step 2에서 추가하고 검증. Mining: LLM이 substrate를 기반으로 runtime에 발생할 수 있는 path의 entrypoint 후보를 제안하여 substrate에 추가. Verification: 별개 LLM 인스턴스가 substrate + 필요시 코드 일부 + entrypoint candidate list를 받아 독립 검증. proposer의 reasoning은 verifier에게 공개하지 않음 (anchoring 방지). verifier는 structured critique schema를 따름: reachability, attacker-controllability, 필요한 가정, 반박 가능한 substrate edge. 목적: 유효한 entrypoint만 substrate에 누적해서 Step 3에서 context가 폭발하는 것을 방지.
- **Step 3 (LLM Evidence IR — 점들을 이어 선을 구성):** runtime-context-conditioned path bundle synthesis. IR 형식은 현 단계에서 느슨하게 두되, 다음 invariant는 강제: 모든 claim은 file:line provenance를 가져야 함, 모든 path는 entry point가 명시되어야 함. sink는 evidence IR에 꼭 포함될 필요는 없고, 목적은 실행 가능한 evidence IR을 모두 끌어내는 것. Evidence IR은 runtime에도 실행 가능한 path를 모두 고려하여 Step 4 layer가 공격 시나리오를 도출할 수 있을 만큼 충분한 정보를 포함해야 함. Retrieval 정책: LLM이 볼 수 있는 코드 범위는 substrate edge 기반 N-hop neighborhood로 결정론적으로 자름 (LLM 자유 선택 금지), N=2로 구현.
- **Step 4 (LLM Attack Scenario — 선들을 엮어서 도형 완성):** Evidence IR(선)들을 엮어 exploit chain을 도출. 도형은 선 하나로 이루어질 수도 있고, 같은 선을 여러 번 다른 순서로 쓸 수 있음. 우선순위는 exploit 가능한 공격 시나리오. 도출한 시나리오에는 Evidence IR들을 엮어 도출한 exploit chain이 반드시 명시되어야 함. Evidence를 엮어서 시나리오를 생성할 때 최소 하나 이상의 sink가 포함되어야 유효한 공격 시나리오가 도출됨.

**핵심: Step 1의 substrate 구축 과정이 잘 진행되면, Step 2와 Step 3에서 LLM이 꼭 봐야 하는 코드량이 기하급수적으로 줄어듦.**

This direction replaces the previous "Evidence IR + Ontology Contract + Early Case Semantics Injection + Typed Projections" direction. The previous direction assumed:

1. A mechanical substrate could produce candidates and Evidence IR without LLM reasoning — disproven by interprocedural patterns invisible to intra-procedural regex.
2. Separating candidate generation from Evidence IR construction was meaningful — disproven when LLM reasons about both simultaneously.
3. LLM should be involved in substrate extraction — unnecessary when hard facts (call graph, state lifecycle, trust boundaries) can be extracted mechanically with higher precision.

---

## 1. Architectural Problem Statement

The current pipeline has exposed the same fundamental weaknesses:

### P1. Regex-based substrate is structurally insufficient

The current substrate (Indexer + Primitives + ScenarioMode) uses regex patterns and keyword matching. This means:

- **Intra-procedural only:** guard_result_used is detected within a single function. Cross-function state sharing (e.g., BootVerifyState global) is invisible.
- **Positive-only detection:** Primitives detect what IS present (guard calls, state assignments). They cannot detect what is MISSING (token not invalidated, state not refreshed) — which is often the vulnerability itself.
- **No semantic understanding:** g_last_validated_time is extracted as a variable name and type. Its role as "session freshness indicator" is not encoded.
- **Profile-driven blind spots:** ScenarioMode filters functions by hardcoded action keywords ("execute", "boot", "launch"). Functions not matching these keywords are never considered.

### P2. No user-context awareness

The substrate extracts all call paths from all functions, with no notion of:

- "this function runs when the user executes fw-update --mode usb",
- "this #ifdef CONFIG_NETWORK block is only compiled in network mode",
- "this code path is unreachable in the current configuration".

The result: candidates are context-agnostic. The LLM in scenario-reason must filter irrelevant candidates without sufficient context — which is speculation, not analysis.

### P3. No entrypoint filtering before LLM reasoning

Static analysis produces an unbounded set of candidates. Every function that contains a guard call, state variable, or conditional branch becomes a candidate. The LLM receives all of them — including trivially irrelevant ones (printf(), memcpy() in logging path, echo() for diagnostics). This explodes the context window and dilutes signal.

### P4. Call graph built via regex despite clang AST availability

When compile_commands.json is present, ClangASTParser extracts functions via clang AST. But the call graph is then rebuilt via regex (callee( pattern matching on function body text). The clang AST already has CallExpr nodes with precise callee information — including indirect calls through function pointers — that are discarded.

### P5. Single-file test fixtures cannot test path-based grouping

The current dataset consists of single .c files with a main() function. Each file is an isolated test case. This cannot test:

- inter-file call graph analysis,
- multi-path execution scenario reasoning,
- overlapping execution paths (same function in different contexts),
- Makefile/compile configuration awareness.

---

## 2. Target Architecture

### The Shape-Metaphor View

Step 1 (extract points) → Step 2 (add starting points) → Step 3 (connect into lines) → Step 4 (weave into shapes)
A line's midpoint can be any point. A line's starting point must be an entry point.
A shape can be a single line, multiple lines combined, or the same line reused in different orders.

### Detailed Pipeline

Source Code (project-level, multi-file) + Build Config (Makefile/compile_commands.json)
  │
  ▼ Step 1: Rule-based Substrate Extraction — extract all POINTS (deterministic, no LLM)
  │  Promise: same input → same output. Not "ground truth" — best extractable static info.
  │  Downstream must tolerate < 100% accuracy.
  │  Output format: unified (no formal fact/heuristic separation).
  │
  │  Categories (all rule-based):
  │  - Call graph: Clang AST CallExpr-based. Direct calls, indirect calls (function pointers).
  │  - Data/control flow: intra-procedural variable defs, uses, conditional branches.
  │  - Guard/enforcement relations: guard calls + result-checking within same function.
  │  - Trust boundaries: IPC endpoints, external I/O, network sockets, file reads.
  │    [heuristic: direction (untrusted→trusted) inferred from rule patterns]
  │  - Config/mode/command triggers: #ifdef blocks, CLI argument parsers, mode switches.
  │    [heuristic: security impact inferred from symbol names and context]
  │  - Callback registrations: function pointer assignments, __attribute__((constructor)),
  │    signal handlers, function table entries.
  │  - Evidence anchors: hard-coded data, key references, magic values, structural artifacts.
  │  -- Excluded: state lifecycle, persistence/cache, privilege transitions
  │     (RTOS/firmware에서 구조적으로 의미가 약하거나 존재하지 않음)
  │
  ▼ Step 2: LLM Entrypoint Mining + Verification — add STARTING POINTS
  │  Mining (Proposer):
  │  - Input: Step 1 substrate (all points)
  │  - LLM proposes entrypoint candidates with runtime-reachability reasoning
  │  - "which functions are entrypoints for user command X?"
  │  - "which config modes are reachable in this build?"
  │  - Filters trivially irrelevant points (echo, logging, diagnostics)
  │
  │  Verification (Verifier) — separate LLM instance:
  │  - Input: substrate + code snippets (as needed) + entrypoint candidate list
  │  - Proposer's reasoning is NOT shared with verifier (anchoring prevention)
  │  - Verifier follows structured critique schema:
  │    - reachability: is this function actually reachable at runtime?
  │    - attacker-controllability: can an attacker control the input at this point?
  │    - assumptions: what must be true for this entrypoint to be reachable?
  │    - refutable substrate edges: does the substrate support or contradict this?
  │  - Output: verified entrypoints accumulated into substrate
  │
  │  Purpose: only valid entrypoints accumulate, preventing Step 3 context explosion.
  │
  ▼ Step 3: LLM Evidence IR Grouping — connect points into LINES
  │  Input: Step 2 entrypoints + Step 1 substrate + targeted code snippets
  │  Task: runtime-context-conditioned path bundle synthesis
  │  Retrieval policy: code visibility determined by substrate edge-based N-hop neighborhood.
  │    Deterministic. No LLM free choice. N=2.
  │  Invariants (enforced):
  │    - Every claim carries file:line provenance
  │    - Every path has explicit entry point
  │  Note: sink is NOT required. Goal is to pull out all executable evidence IRs.
  │  IR format: flexible at current stage, but must contain sufficient information for
  │    Step 4 to derive attack scenarios. Evidence IR considers all runtime-executable paths.
  │
  ▼ Step 4: LLM Attack Scenario Derivation — weave lines into exploit chains
  │  Input: Evidence IR (lines) + targeted code snippets (N-hop neighborhood, N=2)
  │  Priority: exploit-able attack scenarios
  │  Requirement: 도출한 시나리오에는 Evidence IR들을 엮어 도출한 exploit chain 반드시 명시
  │  Validity: Evidence를 엮어서 시나리오를 생성할 때 최소 하나 이상의 sink 포함
  │  A shape can be a single line, multiple lines combined, or same line reused.
  │
  ▼ Evaluation
  │  Gold-standard matching, per-step metrics, honest scoring
### Key design decisions

**D1: Step 1 is deterministic — no LLM**

Step 1 extracts hard facts from source code. Call graphs, function boundaries, type information, variable definitions, #ifdef blocks, function pointer assignments — these are all derivable from AST and build configuration. Using LLM for these would introduce hallucination risk into the foundation that all downstream steps depend on. Deterministic extraction is more reliable, reproducible, and auditable.

**D2: Step 1 produces points; Step 2 adds runtime starting points**

Step 1 extracts all structural facts (points) mechanically. But a line's midpoint can be any point — its starting point must be an entry point. Step 1에서 룰-베이스로 찾기 힘든 runtime 기반 entry point들 ("this function runs when user executes command X", "this handler is registered via constructor")은 Step 2에서 LLM reasoning으로 추가. Step 3은 이 entry point들을 시작점으로 점들을 이어 실행 path의 선을 구성. FP filtering은 부수적인 효과일 뿐 주된 목적이 아님.

**D3: Entrypoint filtering prevents downstream context explosion**

By removing trivially irrelevant functions (logging, diagnostics, string utilities) alongside entrypoint identification, Step 2 ensures that Step 3 receives a signal-dense input rather than the entire substrate. This is the difference between "here are 500 functions, find the attack paths" and "here are 30 security-reachable functions across 3 execution paths."

**D4: Lines can share points and be reused**

The same point (function) appearing in multiple lines (execution paths) is expected and necessary. verify_signature() in USB mode may have different preconditions than in network mode. The Evidence IR captures this by including the function in both clusters with path-specific context. Similarly, a single line can form a complete shape (attack scenario), or the same line can be reused in different orders across different shapes.

**D5: Code snippets, not full files — determined by N-hop neighborhood**

Steps 3 and 4 do not see the entire codebase. They see Evidence IR (structured data from Steps 1-2) plus targeted code snippets. The code visibility is determined by substrate edge-based N-hop neighborhood (N=2), not by LLM free choice. This ensures deterministic, auditable retrieval. The goal: Steps 3/4 see ~10% of the total code, not 100%.

**D6: Confidence and uncertainty are first-class fields**

Every piece of LLM-generated structured data (Steps 2-4) carries confidence (high/medium/low) and uncertainty (what the LLM is unsure about, with referenced line numbers for human verification). This prevents Step 2 hallucination from silently propagating to Steps 3/4.

**D7: Quarantine bucket for entrypoint filtering**

Step 2's removal of false positives must be auditable. Low-confidence removals go to a quarantine bucket rather than being silently deleted. The evaluator reports quarantine hits separately — if a gold vulnerability was quarantined, it's a false negative that must be tracked.

---

## 3. Evidence IR Redesign

The Evidence IR evolves from a per-candidate data structure to an execution-path cluster.

### Current Evidence IR (per-candidate)

EvidenceIR {
  action: "execute_image",
  check: "verify_signature",
  enforcement_strength: "weak",
  inferred_family_candidates: [{"family": "VERIFY_BEFORE_EXECUTE_MISSING", "score": 0.8}],
  ontology_hints_by_family: {...},
  ...
}
### Target Evidence IR (per execution path, Step 3 output)

EvidenceIRCluster {
  path_id: "fw-update --mode usb",
  path_definition: {
    trigger: "user runs fw-update with --mode usb",
    entry_points: ["main() → parse_args() → update_from_usb()"],
    config_flags: ["CONFIG_USB_SUPPORT"],
  },
  members: [
    {
      function: "verify_signature",
      guards_present: ["signature check against stored public key"],
      guards_missing: ["old signature state not invalidated after verify"],
      state_vars_touched: ["verify_result", "g_boot_state"],
      state_vars_NOT_touched: ["g_current_signature"],
      calls_within_path: ["hash_compute()", "crypto_compare()"],
      called_by_within_path: ["update_from_usb()"],
      confidence: "high",
      uncertainty: "g_boot_state may be shared with network path via different initialization",
      relevant_lines: [45, 48-62, 78],
    },
    // ... more functions in this path
  ],
  call_graph_within_path: {...},
  enforcement_landscape: {
    guarded_actions: [{"action": "execute_image", "guard": "verify_signature", "strength": "partial"}],
    unguarded_actions: [{"action": "rollback_to_previous", "guard": "none"}],
  },
  state_lifecycle: {
    "g_boot_state": {"initialized_in": "main", "modified_in": ["verify_signature", "update_from_usb"], "checked_in": ["execute_image"]},
  },
}
### Critical difference

The current IR captures "this function has a guard but doesn't enforce the result." The target IR captures "in this execution path, this function guards this action but leaves this state unmodified, which matters because another function in this path reads that state."

The latter is interprocedural, path-scoped, and includes negative evidence ("state_vars_NOT_touched", "guards_missing"). These require LLM reasoning over deterministic substrate — not mechanical pattern matching.

---

## 4. Dataset Strategy

### 4.1 Authoritative source requirement

Evaluation datasets must be grounded in externally verifiable truth. The hierarchy is:

1. **CVE records with known vulnerable projects** — real vulnerabilities in real codebases with public exploit scenarios
2. **Authoritative benchmark suites** — NIST SARD, Juliet test suites (project-level subsets)
3. **Published research with reproducible cases** — peer-reviewed security datasets with clear provenance
4. **Enterprise security advisories** — vendor-published vulnerability details with fix commits
5. **Synthetic corpora** — controlled stress testing, migration validation, contract testing ONLY; never the basis for capability claims

**Rule: LLM-generated synthetic data is never used for evaluation.** LLM may assist in constructing intermediate representations (Step 1-3 outputs) from authoritative datasets, but the ground truth must come from external sources.

### 4.2 Project-level codebase requirement

Check Me is a **project-level** tool. Evaluation must be performed on project-level codebases — never on isolated files, snippets, or vulnerable functions extracted from their context. The target zone is "non-trivially-sized but not too large to clone, build, and analyze end-to-end". The pipeline requires codebases with:

- **Multiple source files with inter-file dependencies.** Project-level (not single-file). No rigid file-count bound; the binding constraints are (a) self-containedness (§4.2.1) and (b) "not too large" — Linux-kernel-scale projects are out of scope.
- **A build system** (Makefile or compile_commands.json) with at least 2 build configurations
- **Multiple entry points or command modes** (e.g., --mode usb, --mode network, --mode recovery)
- **Interprocedural state sharing** (global variables, shared headers)
- **Known vulnerabilities** with clear gold-standard answers per execution path
- **Both positive and negative cases** (vulnerable paths and secure paths)
- **Ambiguous cases** (paths where multiple vulnerability interpretations are valid)

**Rule: Project-level only.** Check Me is never validated against single-file fixtures, function-level snippets, or hand-extracted vulnerable code. If it cannot be checked out as a real project, it is not a valid dataset entry.

### 4.2.1 Self-contained project requirement

Each dataset project must be **self-contained**. The entire analysis and evaluation pipeline must operate on the project's source code alone. Projects that depend on external codebases (shared libraries from other repos, kernel headers not included in the project) or specific hardware environments (HSM coprocessors, proprietary boot ROMs) are not suitable.

**Rule: You must be able to clone the project, build it, and run the full 4-step pipeline without any external artifacts.**

This means:
- Linux kernel and similarly massive projects are explicitly low priority — they pull in thousands of dependent files and hardware-specific configurations
- Prefer embedded firmware utilities, update daemons, auth services that build as standalone binaries
- If a project requires cross-compilation, the toolchain must be reproducibly available

### 4.2.2 Label construction from CVE patches

**Mandatory precondition:** The vulnerable project must be cloned at the vulnerable commit before any label construction begins. Labels are constructed against the actual cloned source — never against CVE descriptions, patch diffs, or write-ups in isolation. CVE text and patches are inputs to label reasoning, not substitutes for the source code being labeled.

The construction sequence is:

1. **Clone the vulnerable repository at the vulnerable commit.** Identify the commit immediately before the fix commit and check out the project at that revision. Preserve the full source tree, build system, and configuration.
2. **CVE patch analysis** — Read the fix commit and its parent against the cloned source. Identify which functions changed, which guards were added, which state variables were introduced or modified, with file:line references that resolve in the cloned repo.
3. **Attack scenario research** — Search for public exploit write-ups, vendor advisories, or security blog posts that describe how the vulnerability is triggered, and locate the corresponding code paths in the cloned source.
4. **LLM-assisted label construction** — Feed the CVE description, patch diff, attack scenario, and the cloned source code excerpts to the LLM with strict verification rules:
   - Map the vulnerability to execution path inside the cloned source: "user runs command X → enters function A at file:line → vulnerability manifests at function B at file:line"
   - Define gold-standard findings per path (not per function)
   - Identify expected guard absence, missing enforcement, or state lifecycle gaps
   - Cross-reference against patch diff and cloned source to verify the label matches what the fix addresses and where it lives in the tree
5. **Agent self-check (no separate human reviewer)** — The agent that wrote the labels must perform a thorough verification pass before the corpus accepts them. Required checks:
   - Every file:line reference resolves in the cloned source/ tree
   - Every claim cross-references either a patch diff hunk, an authoritative source quote, or a concrete code excerpt in the clone
   - Enum values match schema versions
   - Step 4 attack scenarios contain ≥ 1 sink and an exploit chain that walks Evidence IR ids
   - Every Evidence IR has an explicit entry point
   The check is logged (notes.md or commit body) so reviewers can replay the reasoning.

### 4.3 Dataset collection approach

Collection starts with authoritative sources and proceeds through:

1. **Identify** — CVE records, research papers, enterprise advisories where the vulnerable code is part of a multi-file project (not single-file PoC)
2. **Extract** — Clone the vulnerable project at the vulnerable commit. Preserve build system, configuration, and directory structure
3. **Map** — Match known vulnerability to execution path: "user runs command X → enters function A → vulnerability manifests at function B"
4. **Define gold** — Write gold-standard answers indexed by execution path, not by function: expected findings, vulnerability class, affected path, evidence
5. **Decompose for intermediate evaluation** — LLM assists in generating high-quality intermediate outputs for each Step 1-3 so that each step's quality can be evaluated independently

### 4.4 Intermediate layer evaluation

Each step's output is independently evaluable:

| Step | Output | Evaluation method |
|------|--------|-------------------|
| Step 1 | Substrate (call graph, state lifecycle, etc.) | Structural completeness: all edges present? all states tracked? Compare against hand-verified graph |
| Step 2 | Verified entrypoints + filtered candidates | Precision/recall: were all security-relevant entrypoints retained? Were all trivial FPs removed? Quarantine hits counted |
| Step 3 | Evidence IR clusters | Path coverage: do clusters cover all known vulnerable paths? Is overlap correct? Are guards_missing fields accurate? |
| Step 4 | Attack scenarios | Gold matching: do hypotheses match gold vulnerabilities? Vulnerability class accuracy? Failure mechanism correctness? |

### 4.5 Initial dataset targets

Collection prioritizes:

1. Existing profile scenarios in the repo (secure_boot_chain, auth_session) matched to real CVEs
2. Open-source firmware projects with known CVEs (embedded update utilities, auth daemons)
3. Research paper datasets with reproducible multi-file vulnerable projects

Target: 3-5 project-level datasets with known scenario-based vulnerabilities before Stage 0 implementation begins.

### 4.6 Dataset construction rules (non-negotiable)

1. **Authoritative source required.** Dataset construction must be preceded by external material collection from CVE records, research papers, enterprise security advisories. Evaluation must NEVER be based on LLM-generated synthetic data as ground truth.
2. **Project-level, known scenario match.** Data collection targets project-level codebases where known scenario-based vulnerabilities can be matched. Single-file fixtures, function-level snippets, and hand-extracted vulnerable code are not valid evaluation inputs.
3. **Vulnerable repo clone is mandatory.** Every dataset entry begins by cloning the upstream repository at the vulnerable commit. Labeling, gold construction, and evaluation are all performed against the cloned source tree. CVE text and patches are reasoning inputs; they never replace the source.
4. **Self-contained source.** The entire analysis and evaluation pipeline must operate on the project's source code alone. Projects that depend on external codebases (shared libraries from other repos, kernel headers not included) or specific hardware environments (HSM coprocessors, proprietary boot ROMs) are not suitable.
5. **Right-sized projects.** Project-level but not too large. Linux-kernel-scale projects and similarly massive codebases are out of scope. The target zone is "non-trivially-sized but cloneable, buildable, and analyzable end-to-end".
6. **Full codebase clone, not a subset.** Evaluation operates on the entire cloned project, not extracted files or curated subsets.
7. **CVE patch-driven label construction.** When a CVE does not come with labels in Check Me's required format, construct them through: (a) clone vulnerable repo at vulnerable commit; (b) CVE patch analysis against the cloned tree — read fix commit and parent, identify changed functions, added guards, modified state variables with file:line references that resolve in the clone; (c) attack scenario research — public exploit write-ups, vendor advisories — mapped onto cloned source; (d) LLM-assisted label construction with strict verification — map vulnerability to execution path, define gold findings per path, cross-reference against patch diff and cloned source; (e) agent self-check (file:line resolution, enum compliance, sink ≥ 1, IR entry-point present, claims tied to authoritative source or code excerpt) logged for replay. file:line references in labels must resolve in the clone.
8. **Schemas are versioned and `unknown` is always allowed.** Every gold artifact carries a `schema_version`. Every classification enum (trigger_type, sink_type, impact.category, etc.) reserves an `unknown` member. Cases that do not fit are recorded as `unknown` with a free-text note rather than force-fit into an existing label. Frequent `unknown` clusters trigger a schema-version bump and enum addition.
9. **Intermediate layer evaluation.** LLM constructs high-quality intermediate evaluation datasets for each Step 1-3, enabling per-step quality measurement.

---

## 5. Migration Strategy

Migration is staged. No big-bang rewrite is allowed.

### Stage 0: Deterministic Substrate Foundation

**Goal:** Build Step 1 — deterministic extraction of hard facts from project-level codebases.

**What needs to be built:**

1. **Clang-based call graph extraction** — use CallExpr from clang AST instead of regex. Extract direct calls, indirect calls (via function pointers), and known library calls. Output: edges with source/target function, line numbers, call type (direct/indirect/virtual).

2. **Intra-procedural data flow extraction** — track variable definitions, uses, and conditional branches within functions. Output: data flow chains per function with line numbers.

3. **Guard/enforcement relation extraction** — identify guard calls and result-checking patterns within functions. Output: guard call → enforcement check pairs (or "no enforcement" if result unused).

4. **Trust boundary extraction** — identify IPC endpoints, external I/O, network sockets, file reads. Output: trust boundary list with entry points and data directions.

5. **Config/mode/command trigger extraction** — parse #ifdef blocks, CLI argument parsers, mode switches. Output: configuration dependency graph.

6. **Callback registration extraction** — identify function pointer assignments, signal handler registrations. Output: callback registry with registration sites and invocation patterns.

7. **Evidence anchor extraction** — line numbers, file paths, function signatures for all extracted facts.

**Not in Step 1:** State lifecycle, persistence/cache, and privilege transitions are excluded. In RTOS/firmware contexts, these concepts are structurally weak or absent. They do not belong in the deterministic substrate.

**Exit criteria:**
1. [x] Clang call graph emits an indirect-edge class the regex baseline cannot represent, and is free of preprocessor-disabled-code false positives. (Original wording — "Clang produces more edges than regex" — turned out to misframe the comparison: a naive regex baseline produces *more* edges by sweeping in `#ifdef`-disabled blocks and macro-name false positives. The architectural advantage is precision and indirect-edge coverage. See `out/STAGE0_REGEX_BASELINE_METRICS.md`.)
2. [x] All 7 substrate categories extracted and output as validated JSON
3. [x] Output includes line numbers, file paths, function signatures for all facts
4. [x] Extraction is fully deterministic (same input → same output, no LLM variance)

### Stage 1: Entrypoint Mining and Evidence IR

**Goal:** Build Steps 2 and 3 — LLM entrypoint filtering and execution-path grouping.

**What needs to be built:**

1. **Step 2 LLM prompt** — prompt design for LLM to read Step 1 substrate and produce:
   - Verified entrypoints (which functions are reachable for user command X)
   - Filtered candidate set (trivially irrelevant functions removed)
   - Quarantine bucket (low-confidence removals)
   - Confidence per entrypoint and removal

2. **Entrypoint evaluation gold** — for each dataset project, define gold entrypoints per execution path for precision/recall measurement

3. **Step 3 LLM prompt** — prompt design for LLM to take verified entrypoints + substrate + code snippets and produce Evidence IR clusters (Section 3 schema)

4. **Code snippet extraction** — given line numbers from Step 1, extract minimal relevant snippets for Step 3

**Exit criteria:**
1. [ ] Entrypoint precision >= 90% on test datasets (few false positives passed to Step 3)
2. [ ] Entrypoint recall >= 95% on test datasets (no security-relevant entrypoints lost)
3. [ ] Quarantine hits tracked and reported separately
4. [ ] Evidence IR clusters built for all defined paths in test projects
5. [ ] Functions correctly appear in multiple clusters (overlap verified)
6. [ ] Code snippets in clusters total < 30% of original source lines

### Stage 2: Attack Scenario Generation

**Goal:** Build Step 4 — attack scenario derivation from Evidence IR.

**What needs to be built:**

1. **Step 4 LLM prompt** — prompt design for LLM to take Evidence IR clusters + code snippets and produce attack scenarios with vulnerability class, security property, failure mechanism

2. **Hypothesis output schema** — structured format matching evaluation expectations

3. **Integration with evaluation** — connect hypothesis output to existing benchmark_runner A/B harness

**Exit criteria:**
1. [ ] Hypotheses generated for all Evidence IR clusters in test projects
2. [ ] Hypotheses reference specific functions and line numbers (grounded, not free-form)
3. [ ] Gold matching achieves meaningful recall on test projects (baseline established)
4. [ ] Steps 3/4 LLM sees < 30% of total source lines

### Stage 3: Full Pipeline Evaluation

**Goal:** Establish evaluation discipline for the complete 4-step pipeline.

**What needs to be built:**

1. **End-to-end evaluation** — run full pipeline on all project-level datasets, measure recall/precision at each step

2. **A/B comparison** — run both old (scenario_mode) and new (4-step) pipelines on overlapping test cases

3. **Cost analysis** — measure LLM token usage per step. Verify Steps 3/4 see significantly less code than Step 1

4. **Quarantine audit** — review all quarantined candidates: any false negatives? adjust Step 2 thresholds

**Exit criteria:**
1. [ ] New pipeline finds >= all vulnerabilities found by old pipeline (on overlapping cases)
2. [ ] New pipeline finds additional vulnerabilities that old pipeline missed
3. [ ] Steps 3/4 LLM sees < 30% of total source lines
4. [ ] No self-reinforcing evaluation (evaluator does not share ontology with hypothesis generator)
5. [ ] All dataset ground truths traceable to authoritative external sources

---

## 6. Core Design Rules

### Rule 1: Step 1 is the ceiling
Steps 2-4 cannot produce results that Step 1 does not contain. If Step 1 misses a call edge or state variable, downstream steps will not know it exists. Invest in Step 1 completeness and precision.

### Rule 2: Step 1 is deterministic — not ground truth
No LLM in Step 1. The substrate promise is "same input → same output", not "100% correct".
Some categories (trust boundaries, mode triggers) use rule-based heuristics that may produce imperfect results.
Downstream steps must tolerate and work around substrate imperfections.
Output format is unified: no formal separation between fact and heuristic.

### Rule 2b: Step 2 separates proposing from verifying
Entrypoint candidates are proposed by one LLM instance and verified by another.
The proposer's reasoning is never shared with the verifier (anchoring prevention).
The verifier uses a structured critique schema: reachability, attacker-controllability, assumptions, refutable substrate edges.

### Rule 3: Confidence and uncertainty are mandatory
Every LLM-generated field (Steps 2-4) must carry confidence and uncertainty. No exceptions. This is the mechanism by which downstream steps know when to re-read source code.

### Rule 4: Quarantine is auditable
Step 2's false positive removals must be trackable. Low-confidence removals go to quarantine, not silence. The evaluator reports quarantine hits — if a gold vulnerability was quarantined, it's a measured false negative.

### Rule 5: Evidence IR is the source of truth
Once Step 3 produces Evidence IR, Steps 4 and Evaluation derive from it. They do not rebuild semantics from raw source code.

### Rule 6: Overlap is intentional
A function appearing in multiple Evidence IR clusters is correct, not a bug. Each cluster captures the function in a different execution context.

### Rule 7: Evaluation must remain honest
No circular shortcuts. No shared ontology between hypothesis generator and evaluator. No hiding weak paths behind permanent exceptions.

### Rule 8: Ground truth is external
Evaluation datasets trace to CVEs, authoritative benchmarks, or published research. LLM-generated synthetic data is never the basis for capability claims.

### Rule 9: Fix causes, not symptoms
Whenever a change is proposed, classify it as structural improvement or local patch. Structural improvements are preferred.

### Rule 10: Project-level datasets are first-class
Single-file fixtures are useful for primitive unit tests but insufficient for pipeline validation. The pipeline is designed and tested on project-level codebases.

### Rule 11: Retrieval is deterministic, not LLM-chosen
The code that Steps 3/4 LLM can see is determined by substrate edge-based N-hop neighborhood (N=2), not by LLM's free selection. This prevents the LLM from cherry-picking supportive evidence while ignoring contradictory code.

---

## 7. Explicit Non-Goals

These are not current goals:

- permanently running "main track" and "exception track" as product architecture,
- endlessly splitting profiles into separate operational silos,
- relying on LLM strength alone to recover weak substrate,
- replacing all deterministic analysis with model improvisation,
- tuning only for benchmark optics,
- full corpus rewrite in a single phase,
- making Steps 3/4 completely code-free (they will see snippets, ~10% of source),
- LLM-generated evaluation datasets,
- putting LLM in Step 1 (deterministic extraction is superior for hard facts).

---

## 8. Decision Rules for New Changes

Every non-trivial change should be classified before implementation.

### A. Structural Improvement
A change is structural if it:
- reduces semantics drift,
- strengthens shared contracts,
- improves multiple profiles or modes,
- reduces evaluator compensation logic,
- improves generality.

### B. Local Patch
A change is local if it:
- fixes one profile only,
- introduces profile-specific exceptions,
- adds one-off mapping without improving the shared contract,
- mainly serves score recovery without architectural benefit.

Local patches are allowed only when needed to unblock diagnosis, clearly labeled as transitional, and not mistaken for final architecture.

---

## 9. Evaluation Principles

### 9.1 Official vs Diagnostic
Official scoring must use gold data, raw generated artifacts, and evaluator logic. Diagnostic shortcuts must never be confused with official scores.

### 9.2 Metrics must remain interpretable
If a metric changes, we must be able to explain why: structural improvement, evaluator repair, ontology repair, contract repair, interpretation improvement, or artifact inflation.

### 9.3 Live must earn superiority
Live mode must not be declared superior merely because it is live. It must outperform mock on meaningful interpretation metrics while preserving honesty and grounding.

### 9.4 No self-reinforcing evaluation
The evaluator must not share ontology with the hypothesis generator in a way that creates tautological matches. If the hypothesis generator uses ontology to map family → vulnerability_class, the evaluator must not use the same ontology to verify the match.

### 9.5 Per-step evaluation
Each step's output (Steps 1-4) must be independently evaluable. Pipeline failure at Step 4 is not useful if we cannot determine whether the cause was Step 1 incompleteness, Step 2 over-filtering, Step 3 incorrect grouping, or Step 4 poor reasoning.

### 9.6 Dataset claims must remain honest
Improvements on synthetic-dev or narrowly scoped pilot fixtures must not be overstated as broad real-world capability gains.

---

## 10. Risks to Avoid

### R1. Step 1 incompleteness
If deterministic extraction misses structural facts (e.g., indirect calls through function pointers that clang resolves), downstream LLM steps have no way to recover them. Mitigation: comprehensive Step 1 evaluation against hand-verified call graphs on test datasets.

### R2. Step 2 false negatives
Step 2's entrypoint filtering may remove security-relevant candidates as "irrelevant." Mitigation: quarantine bucket for low-confidence removals, separate reporting, periodic audit of quarantine hits.

### R3. Big-bang migration risk
Too much simultaneous change makes rollback and diagnosis expensive. Mitigation: staged migration (Stage 0-3), A/B comparison at each stage.

### R4. LLM cost explosion
Running LLM on full substrate in Step 2 is expensive for large codebases. Mitigation: Step 1 substrate is structured JSON (smaller than source). Step 2 operates on substrate, not source code. Step 1 runs once (cached).

### R5. Evaluation illusion
Score gains caused by contract/evaluator repair must not be misdescribed as model capability gains.

### R6. Over-engineering Evidence IR
The Evidence IR schema must be expressive enough for Step 4 but not so complex that Step 3 struggles to populate it. Start minimal, expand based on Step 4 feedback.

### R7. Weak-data optimism
Architecture success claimed only on weakly grounded or synthetic-only data will create false confidence.

---

## 11. Success Criteria

Check Me is moving in the right direction if, over time:

1. fewer fixes are profile-specific,
2. more fixes improve shared semantics,
3. hypothesis generation relies more on Evidence IR than raw source code,
4. evaluator blind spots decrease,
5. the pipeline finds vulnerabilities that the old mechanical substrate missed,
6. code mode and scenario mode converge onto the same 4-step pipeline,
7. benchmark coverage becomes broader and more externally grounded,
8. each step's output can be evaluated independently with clear metrics.

---

## 12. Branching and Migration Discipline

Structural migration work should not be performed as uncontrolled in-place rewrite on the main working line.

Recommended discipline:

- keep the current repo history and current branch as the stable baseline,
- create a dedicated long-lived architecture branch for the 4-step pipeline migration,
- merge back in slices only after shadow/canary validation,
- preserve benchmark comparability across versions,
- use versioned docs and migration checkpoints.

The purpose is not bureaucracy. It is to make rollback, comparison, and re-entry affordable.

---

## 13. Final Standard

The final standard is not:
- "some profiles are operational."

The final standard is:
- "Check Me has one coherent architecture, one deterministic substrate + 3-step LLM pipeline over structured Evidence IR, one credible dataset program built on project-level codebases from authoritative sources, and one honest evaluation path."

That is the direction all implementation work must serve.

---

## Appendix A: Current Infrastructure State (2026-04-28)

### Completed fixes (2026-04-28):
- Gold file discovery: gold_*.json strategy added to benchmark_runner (stable 0→4, experimental 4→12)
- Tier detection: EXPERIMENTAL and CANARY tiers added (all paths eval-enabled)
- Ambiguity pilot: gold files renamed to uppercase-with-hyphen (4/4 discoverable)
- Registry: counting_methodology documented, ambiguity_pilot mirror added
- Fixture regen: ambiguity_pilot added to regen_[[fixtures.py](http://fixtures.py)](http://fixtures.py) canary mapping

### Known issues (not blocking new architecture):
- 23 failing tests (19 fixture missing from archive migration, 6 LLM mock config incomplete)
- Code mode CWE416: no gold.json files (benchmark discovers 0 cases)
- Schema validator: regex pattern check is dead code (silently passes)
- 14 scripts reference stale paths (documented in path_redirects.json)

### Artifact inventory:
- Scenario mode: 35 discoverable cases (stable 4, experimental 12, ab_pilot 15, ambiguity_pilot 4)
- Code mode: 120 CWE416 .c files (no gold, not benchmarkable)
- Synthetic truth: 28 micro_truth cases
- Ingest queue: 1096 .c files (raw, no metadata)
