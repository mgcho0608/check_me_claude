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

### Self-check는 직접 수행 (스크립트 금지)

라벨 작성 후 self-check는 **agent가 직접, 손으로** 수행한다. 자동 스크립트로 통째로 돌려놓고 "OK 떴다"로 통과시키지 않는다. 이유: regex 기반 자동 검증은 매크로(예: `PROCESS_THREAD`), `static` 함수, 익명/wrapper 함수 같은 케이스를 놓치고, "OK"라는 결과가 검증의 깊이를 가린다. 실제 데이터셋 라벨링에서 이 함정에 한 번 빠진 적 있음 (contiki-ng audit log A2-A4, A7 참조).

#### 절차 (모든 gold 항목에 대해 한 항목씩)

1. **gold 파일에서 (file, line, function) 한 쌍 선택.**
2. **`Read` 도구로 해당 file의 해당 line 주변 ±10라인을 직접 읽는다.**
3. **다음 4가지를 눈으로 확인한다:**
   - 인용한 line의 텍스트가 claim 내용과 실제로 일치하는가
   - 그 line을 둘러싼 enclosing function 이름이 gold가 주장하는 함수명과 같은가
   - 함수 시그니처(반환형, 파라미터)가 자연스러운가 (매크로 잡힌 건 아닌가)
   - claim이 가리키는 의미적 역할(guard / sink / call edge / trust boundary 등)이 코드와 부합하는가
4. **불일치를 발견하면 즉시 수정하고 그 이유를 `notes.md` audit log에 적는다.**

#### 항목 (모두 직접 손으로 검증)

- [ ] 모든 file:line 참조가 `source/` 안에서 resolve되며, 인용 line text + enclosing function 둘 다 직접 본 코드와 일치
- [ ] 모든 claim이 patch diff hunk / authoritative source 인용 / 클론 코드 excerpt 중 하나로 backing되고, 그 backing이 실제로 해당 claim을 뒷받침하는지 한 번 더 읽어 확인
- [ ] enum 값이 현재 `schemas/` 의 schema_version과 일치하며, `unknown` 사용 시에는 free-text 사유가 동반됨
- [ ] AttackScenario에 exploit_chain + sink ≥ 1 명시
- [ ] 모든 EvidenceIR에 entry point 명시
- [ ] Step 2 entrypoint들에 supporting substrate edges 또는 quarantine 사유 명시
- [ ] Step 1 substrate에 absence(없는 것)를 facts로 넣지 않음 (absence 관련 의미는 IR `conditions.blocking` 또는 `guards_missing`에 둠)
- [ ] `notes.md` self-check 로그가 실제 검증 결과와 일치 (검증 안 한 항목을 "OK"로 적지 않음)

#### 보조 도구 사용은 허용, 단 결론은 직접

- `grep`, `git show`, `git log` 같은 read-only 보조 도구는 **항목을 찾기 위해서만** 사용 가능.
- 자동 audit 스크립트가 이미 있어도 **돌리지 않는다**. 결론은 항상 agent가 직접 코드를 읽고 내린다.
- 의심스러운 한 항목당 최소 한 번은 `Read`로 source 파일을 직접 열어본다.

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
