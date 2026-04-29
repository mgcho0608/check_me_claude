# Aegis Inspect — PLAN

이 문서는 Aegis Inspect의 **설계 기준서이자 에이전트 작업 기준서**다.
AI Agent는 이 문서를 최우선으로 읽고 작업한다.

원칙:
- README는 짧게 유지한다.
- 설계 철학, 작업 원칙, 구현 우선순위는 이 문서가 source of truth다.
- 구현이 바뀌면 이 문서를 먼저 갱신한다.
- 문서가 구현보다 앞서 강한 claim을 하지 않는다.

---

# 1. 제품 정의

**Aegis Inspect**는 C/C++ 코드베이스를 대상으로, 4단계 파이프라인을 통해 **exploit 가능한 공격 시나리오**를 도출하는 보안 분석 도구다.

핵심 방향:
> **결정론적 substrate 추출 → LLM entrypoint mining + 검증 → LLM Evidence IR 구성 → LLM 공격 시나리오 도출**

산출물은 security candidate가 아니라 **공격 시나리오(AttackScenario)** 와 그것을 뒷받침하는 **Evidence IR**이다.

---

# 2. 핵심 멘탈 모델: Points → Lines → Shapes

```
Step 1 → 점(point)을 찾는다
Step 2 → 선의 시작점(entry point)을 추가·검증한다
Step 3 → 점들을 이어 선(Evidence IR)을 구성한다
Step 4 → 선들을 엮어 도형(공격 시나리오)을 완성한다
```

- 선의 시작점은 반드시 entry point여야 한다. 중간 지점은 어떤 점이든 될 수 있다.
- 도형은 선 하나로 이루어질 수도 있고, 같은 선을 여러 번 다른 순서로 쓸 수 있다.
- Step 1 substrate가 정밀할수록 Step 2~3에서 LLM이 봐야 하는 코드량이 기하급수적으로 줄어든다.

---

# 3. 4단계 파이프라인

## Step 1 — 결정론적 Substrate 구축 (점 추출)

**주체:** rule-based extractor. LLM 없음.

**약속:** 동일 입력 → 동일 출력. "ground truth"가 아니라 추출 가능한 최선의 정적 정보.
downstream은 100% 정확하지 않을 수 있음을 인지하고 동작한다.
출력 형식은 단일 형태로 통일된다 (fact / heuristic을 형식적으로 구분하지 않음).

**추출 항목:**

| 항목 | 설명 |
|------|------|
| Call graph | Clang AST `CallExpr` 기반. 직접 호출, 함수 포인터 간접 호출 포함 |
| Data/control flow | 함수 내 변수 def/use, 조건 분기 (intra-procedural) |
| Guard/enforcement 관계 | guard 호출 + 동일 함수 내 result-checking 패턴 |
| Trust boundary | IPC endpoint, 외부 I/O, 네트워크 소켓, 파일 읽기 (방향은 heuristic) |
| Config/mode/command trigger | `#ifdef` 블록, CLI 인자 파서, 모드 스위치 (security impact는 heuristic) |
| Callback registration | 함수 포인터 할당, signal handler, `__attribute__((constructor))`, 함수 테이블 등록 |
| Evidence anchor | 하드코딩 데이터, key 참조, magic value, 구조적 artifact의 file:line |

**제외 항목:** state lifecycle, persistence/cache, privilege transition
(RTOS/firmware 환경에서 구조적으로 의미가 약하거나 존재하지 않음)

**Exit criteria:**
- [ ] Clang 기반 call graph가 regex 대비 더 많은 edge를 생성함 (동일 입력 기준)
- [ ] 7개 항목 모두 JSON으로 추출되고 line number, file path, function signature 포함
- [ ] 완전 결정론적 (LLM variance 없음)

---

## Step 2 — LLM Entrypoint Mining + Verification (선의 시작점 추가)

**목적:** Step 1의 rule-based로 찾기 어려운 runtime 기반 entry point를 추가하고 검증한다.
유효한 entry point만 substrate에 누적하여 Step 3의 context 폭발을 방지한다.

### Mining (Proposer)
- 입력: Step 1 substrate
- LLM이 runtime에 발생 가능한 path의 entrypoint 후보를 제안
- "커맨드 X 실행 시 어느 함수가 entry point인가", "이 빌드에서 어떤 config mode가 도달 가능한가"

### Verification (Verifier)
- 별개 LLM 인스턴스가 독립 검증
- Proposer의 reasoning은 Verifier에게 공개하지 않음 (anchoring 방지)
- Structured critique schema를 따름:
  - **reachability:** 이 함수가 runtime에 실제로 도달 가능한가
  - **attacker-controllability:** 공격자가 이 지점의 입력을 제어할 수 있는가
  - **assumptions:** 이 entry point가 도달 가능하기 위해 필요한 가정
  - **refutable substrate edges:** substrate가 이를 뒷받침하는가, 반박하는가
- 출력: 검증된 entry point → substrate에 누적
- 낮은 신뢰도의 제거 후보는 **quarantine bucket**에 보관 (silent delete 금지)

**Exit criteria:**
- [ ] Entrypoint precision ≥ 90% (test dataset 기준)
- [ ] Entrypoint recall ≥ 95% (보안 관련 entry point 누락 없음)
- [ ] Quarantine hit 별도 추적 및 보고

---

## Step 3 — LLM Evidence IR 구성 (선 구성)

**목적:** runtime-context-conditioned path bundle synthesis.
Step 2 entry point를 시작점으로 점들을 이어 실행 path의 선을 구성한다.

**Retrieval 정책:**
- LLM이 볼 수 있는 코드 범위는 substrate edge 기반 N-hop neighborhood로 결정론적으로 자름
- LLM의 자유 선택 금지
- default N=2, escalation policy 허용

**강제 invariant:**
- 모든 path에는 entry point가 명시되어야 함
- 모든 claim은 file:line provenance를 가져야 함
- sink는 IR에 꼭 포함될 필요 없음 — 목적은 runtime에 실행 가능한 Evidence IR을 모두 끌어내는 것

**Evidence IR Schema:**
```yaml
EvidenceIR:
  id: string

  entrypoint:
    function: string
    file: string
    line: integer | null

  runtime_context:
    trigger_type: command | config | callback | event | boot_phase | unknown
    trigger_ref: string | null

  path:
    nodes:
      - function: string
        file: string
        line: integer | null
        role: entry | guard | sink | intermediate | unknown
    edges:
      - from: string
        to: string
        kind: call | dataflow | controlflow | callback | config | state

  conditions:
    required:
      - string
    blocking:
      - string

  evidence:
    anchors:
      - file: string
        line_start: integer
        line_end: integer
        note: string

  confidence:
    level: high | medium | low
    reason: string
```

**Exit criteria:**
- [ ] Evidence IR cluster가 test project의 모든 알려진 취약 path를 커버
- [ ] 동일 함수가 여러 cluster에 등장하는 것은 정상 (path별 context 차이)
- [ ] Cluster 내 코드 snippet 합계 < 전체 소스 라인의 30%

---

## Step 4 — LLM 공격 시나리오 도출 (도형 완성)

**목적:** Evidence IR(선)들을 엮어 exploit chain을 도출한다.

**필수 조건:**
- 도출한 시나리오에는 Evidence IR들을 엮어 도출한 exploit chain이 반드시 명시되어야 함
- Evidence를 엮어 시나리오를 생성할 때 최소 하나 이상의 sink가 포함되어야 유효한 공격 시나리오

**AttackScenario Schema:**
```yaml
AttackScenario:
  id: string
  title: string

  exploit_chain:
    steps:
      - order: integer
        evidence_ir: string
        action: string
        result: string

  sink:
    function: string
    file: string
    line: integer | null
    sink_type: memory_write | command_execution | auth_bypass | crypto_misuse |
               info_leak | state_corruption | resource_exhaustion | unknown

  impact:
    category: memory_corruption | privilege_bypass | data_leak | denial_of_service |
              integrity_violation | crypto_break | unknown
    description: string

  verdict:
    exploitability: high | medium | low | unproven
    confidence: high | medium | low
    reason: string
```

**Exit criteria:**
- [ ] 시나리오마다 exploit chain + 최소 1개 sink 명시
- [ ] 시나리오가 specific function과 line number를 참조함 (free-form 금지)
- [ ] Steps 3/4 LLM이 보는 코드 < 전체 소스 라인의 30%

---

# 4. 핵심 설계 규칙

**Rule 1: Step 1은 천장이다**
Steps 2-4는 Step 1이 담지 않은 정보를 생성할 수 없다. Step 1 completeness에 투자한다.

**Rule 2: Step 1은 결정론적이다 — ground truth가 아니다**
Step 1에 LLM 없음. "동일 입력 → 동일 출력"이 약속이지 "100% 정확"이 약속이 아니다.
Downstream은 substrate 불완전성을 인지하고 동작한다.

**Rule 3: Step 2는 proposing과 verifying을 분리한다**
Proposer reasoning은 Verifier에게 공개하지 않는다. Verifier는 structured critique schema를 따른다.

**Rule 4: Confidence와 uncertainty는 필수 필드다**
모든 LLM 생성 구조체(Steps 2-4)는 `confidence`와 근거를 담는다. 예외 없음.

**Rule 5: Quarantine은 감사 가능해야 한다**
Step 2의 false positive 제거는 추적 가능해야 한다. 낮은 신뢰도 제거는 quarantine으로, silent delete 금지.

**Rule 6: Retrieval은 결정론적이다**
Steps 3/4 LLM이 볼 수 있는 코드는 substrate edge 기반 N-hop neighborhood로 결정론적으로 자른다.
LLM 자유 선택 금지.

**Rule 7: Evidence IR이 source of truth다**
Step 3가 Evidence IR을 생성하면, Step 4와 평가는 이를 기반으로 동작한다. raw source에서 semantics를 재구성하지 않는다.

**Rule 8: Overlap은 의도된 설계다**
동일 함수가 여러 Evidence IR cluster에 등장하는 것은 버그가 아니다. 각 cluster는 해당 함수를 다른 실행 context에서 포착한다.

**Rule 9: Ground truth는 외부에서 온다**
평가 데이터셋은 CVE, authoritative benchmark, 출판된 연구에서 trace 가능해야 한다.
LLM 생성 synthetic data를 capability claim의 근거로 삼지 않는다.

**Rule 10: Project-level dataset이 first-class다**
단일 파일 fixture는 primitive unit test에는 유용하지만 pipeline 검증에는 불충분하다.

---

# 5. 데이터셋 전략

## 5.1 요건

- **출처:** CVE, 연구 논문, 대기업 보안 어드바이저리 등 공신력 있는 외부 자료 선행 수집 필수
- **규모:** 단일 파일 아님. 10-20개 소스 파일, 빌드 시스템(Makefile / compile_commands.json), 복수 실행 모드
- **self-contained:** 해당 프로젝트 소스코드만으로 전체 분석·평가 파이프라인이 동작해야 함
  - 외부 레포 의존, 하드웨어 환경(HSM, proprietary boot ROM) 의존 데이터셋 부적합
  - Linux kernel 등 매우 큰 프로젝트 후순위
- **라벨:** CVE 패치 분석 + 공격 시나리오 조사 + LLM 보조 라벨 구성 + 사람 검증

## 5.2 라벨 구성 원칙 (CVE patch-driven)

1. **CVE 패치 분석** — fix commit과 parent를 읽어 변경 함수, 추가된 guard, 수정된 상태 변수 식별
2. **공격 시나리오 조사** — public exploit write-up, vendor advisory 수집
3. **LLM 보조 라벨 구성** — CVE 설명 + patch diff + 공격 시나리오를 입력으로:
   - 취약점을 실행 path로 매핑 ("커맨드 X → 함수 A 진입 → 함수 B에서 취약점 발현")
   - Gold-standard finding을 path 단위로 정의 (함수 단위 아님)
   - patch diff와 교차 검증
4. **사람 검증** — 모든 LLM 구성 라벨은 원본 CVE와 patch 대비 검토 후 corpus에 등록

## 5.3 중간 평가

각 step 산출물은 독립적으로 평가 가능해야 한다:

| Step | 산출물 | 평가 방법 |
|------|--------|-----------|
| Step 1 | Substrate | 구조적 completeness: 모든 edge, 모든 state 추적 여부. hand-verified graph 대비 비교 |
| Step 2 | Verified entrypoints | Precision/recall: 보안 관련 entry point 보존 여부, trivial FP 제거 여부. Quarantine hit 집계 |
| Step 3 | Evidence IR clusters | Path coverage: 알려진 취약 path 커버 여부. guards_missing 정확성 |
| Step 4 | Attack scenarios | Gold matching: 시나리오가 gold vulnerability와 매칭되는가 |

---

# 6. 마이그레이션 전략

단계적으로 진행한다. Big-bang rewrite 금지.

## Stage 0 — 결정론적 Substrate 구축
Step 1 구현. Clang AST 기반 call graph, 7개 substrate 항목 추출.

## Stage 1 — Entrypoint Mining + Evidence IR
Step 2, 3 구현. LLM prompt 설계, code snippet 추출, quarantine bucket.

## Stage 2 — 공격 시나리오 생성
Step 4 구현. AttackScenario schema 연동, 평가 harness 연결.

## Stage 3 — 전체 파이프라인 평가
End-to-end 평가, A/B 비교 (구 scenario_mode vs 신 4-step), cost 분석, quarantine audit.

---

# 7. 에이전트 작업 규칙

1. README는 짧게 유지한다.
2. 새 기능은 반드시 CLI subcommand로 먼저 노출한다.
3. Step 1 구현에서 LLM을 쓰지 않는다.
4. substrate 항목을 fact / heuristic으로 형식 분리하지 않는다.
5. Evidence IR마다 entry point와 file:line provenance가 있는지 확인한다.
6. AttackScenario에 exploit chain과 sink가 명시되어 있는지 확인한다.
7. 구현이 바뀌면 이 문서를 먼저 갱신한다.
8. 현재 구현보다 강한 claim을 문서에 쓰지 않는다.
9. dataset ground truth는 외부 출처에서 trace 가능해야 한다.

---

# 8. 현재 상태

## 구 구현 (archive/v0-old-design)
- `check_me` v0.1.0: regex 기반 heuristic indexer, scenario mode, code mode
- 83개 테스트, 5개 도메인 프로필, 15개 candidate family
- 한계: intra-procedural only, positive-only detection, regex call graph, single-file fixture

## 현재 방향
- Stage 0 (결정론적 Substrate) 구현 전
- 기존 소스 구조는 archive 브랜치에 보존
- 신규 구현은 4-step 파이프라인 기준으로 진행

---

# 9. 한 줄 결론

Aegis Inspect는 **결정론적 substrate → LLM entrypoint mining → Evidence IR → 공격 시나리오**의 4단계 파이프라인으로, project-level C/C++ 코드베이스에서 exploit 가능한 공격 시나리오를 도출하는 도구다.
