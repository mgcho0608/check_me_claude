# Claude Agent 행동규칙 — Check Me

## 세션 시작 시 (필수)
1. `PLAN.md`를 가장 먼저 읽는다 — source of truth.
2. 현재 작업 위치(브랜치, 디렉토리)와 PLAN.md의 Stage 0-3 상태를 맞춘다.
3. 데이터셋 작업 중이면 해당 `datasets/<project>-<cve>/` 의 `metadata.json`과 `notes.md`를 읽는다.

## 4-step 파이프라인 핵심 규칙

### Step 1 (Substrate, deterministic)
- LLM 사용 금지. Clang AST + 정적 룰만 사용.
- 출력은 7개 카테고리(call graph / data·control flow / guards / trust boundaries / config·mode·command triggers / callbacks / evidence anchors).
- 출력 형식 통일 — fact/heuristic을 형식적으로 분리하지 않음.
- 약속은 "동일 입력 → 동일 출력"이지 "100% 정확"이 아님.

### Step 2 (Entrypoint mining + verification)
- Proposer와 Verifier는 **별개 LLM 인스턴스**. Proposer의 reasoning을 Verifier에게 노출 금지 (anchoring 방지).
- Verifier는 structured critique schema 따름: reachability / attacker-controllability / assumptions / refutable substrate edges.
- 낮은 신뢰도의 entrypoint는 silent delete 금지 — `status: quarantined`로 보존, audit 가능.

### Step 3 (Evidence IR)
- Retrieval은 결정론적: substrate edge 기반 N-hop neighborhood, **N=2 hybrid** (call edges + 1차 set이 read/write하는 shared global state를 함께 다루는 함수).
- LLM의 자유 코드 선택 금지.
- 모든 IR claim은 file:line provenance 필수.
- 모든 IR에 entry point 명시 필수.

### Step 4 (Attack scenarios)
- 입력은 Evidence IR + N-hop neighborhood 코드.
- 출력 시나리오는 exploit chain 명시 + 최소 1개 sink 포함 필수.
- Evidence IR id를 walk하는 chain으로 표현.

## 모든 LLM 출력 (Step 2-4)에서 강제
- `confidence: high | medium | low` 필수.
- `uncertainty` 자유텍스트 필드 + 관련 line number 필수.
- `schema_version` 필드 포함.

## 데이터셋 작업 규칙
- **취약 repo는 반드시 vulnerable commit으로 클론**해서 `datasets/<project>-<cve>/source/` 에 통째로 둔다. CVE 텍스트나 patch diff만으로 라벨링하지 않는다.
- Project-level만 — single-file fixture, function snippet, hand-extracted 코드 모두 거부.
- Self-contained 필수 — 외부 repo / 특수 하드웨어 의존 프로젝트 거부.
- 사이즈는 project-scale이되 Linux-kernel-scale 거부.
- **사람 검증 단계는 없다**. Agent 자신이 self-check를 수행하고 그 로그를 commit body 또는 `notes.md`에 남긴다.

### Self-check 항목 (라벨 작성 후 반드시 수행)
- [ ] 모든 file:line 참조가 `source/` 안에서 resolve됨
- [ ] 모든 claim이 patch diff hunk / authoritative source 인용 / 클론 코드 excerpt 중 하나로 backing됨
- [ ] enum 값이 현재 `schemas/` 의 schema_version과 일치
- [ ] AttackScenario에 exploit_chain + sink ≥ 1 명시
- [ ] 모든 EvidenceIR에 entry point 명시
- [ ] Step 2 entrypoint들에 supporting substrate edges 또는 quarantine 사유 명시

## 핵심 metadata.json 필드 (최소)
`project`, `cve`, `repo_url`, `vulnerable_commit`, `fix_commit`, `build_commands`, `vulnerability_summary`, `attack_entry_modes`, `key_files`, `authoritative_sources`, `self_contained: true`.

## 일반 행동 규칙
- PLAN.md가 source of truth. 구현이 PLAN과 어긋나면 PLAN을 먼저 갱신한다.
- 현재 구현보다 강한 claim을 문서에 쓰지 않는다.
- 큰 변경은 단계적으로 — big-bang rewrite 금지.
- LLM 합성 데이터를 평가의 ground truth로 쓰지 않는다.

## 프로젝트 경로
- Repo root: `/home/user/check_me_claude`
- 핵심 문서: `PLAN.md`, `README.md`, `CLAUDE.md`, `datasets/WORKFLOW.md`
- Schemas: `schemas/`
- Datasets: `datasets/<project>-<cve>/{metadata.json, source/, gold/, notes.md}`
- Remote: `https://github.com/mgcho0608/check_me_claude`
