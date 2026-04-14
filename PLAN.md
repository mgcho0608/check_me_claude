# check_me PLAN

이 문서는 `check_me`의 **설계 기준서이자 에이전트 작업 기준서**다.
앞으로 AI Agent는 이 문서를 최우선으로 읽고 작업해야 한다.

원칙:
- README는 짧게 유지한다.
- 설계 철학, 작업 원칙, 구현 우선순위, 검증 기준은 이 문서에 유지한다.
- 새로운 phase 요약 문서를 계속 늘리지 않는다.
- 구현이 바뀌면 이 문서를 갱신한다.
- **사용자/에이전트의 공식 실행 경로는 CLI 하나로 통일한다.**

---

# 1. 제품 정의

`check_me`는 **C/C++-first 결정론적 정적 보안 후보 생성 도구**다.

이 도구는 다음을 목표로 한다.
- 코드와 시스템 보안 약속 위반 가능성을 구조적으로 드러낸다.
- 후보를 생성하고, 그 후보를 뒷받침하는 evidence를 남긴다.
- 불확실성을 숨기지 않는다.
- 나중에 LLM이 붙더라도, LLM이 탐지기가 아니라 **해석기**로 동작하도록 기반을 만든다.

`check_me`의 핵심 산출물은 **vulnerability finding**이 아니라 **security candidate**다.

---

# 2. 최상위 철학

## 2.1 Deterministic first
탐지와 후보 생성은 결정론적이어야 한다.
동일 입력이면 동일하거나 구조적으로 동일한 결과가 나와야 한다.

## 2.2 Candidate, not verdict
산출물은 후보여야 한다.
선호 표현:
- structurally identified candidate
- structural concern
- low-confidence candidate
- moderate-confidence structural concern

금지 표현:
- proven vulnerability
- exploitable
- execution-path verified
- race detected
- timing attack detected
- cryptographic weakness proven

## 2.3 Evidence over impression
모든 주요 후보는 evidence를 가져야 한다.
가능하면 아래를 조합한다.
- file:line
- function id / function name
- call graph relation
- result-use signal
- enforcement link
- state lifecycle hint
- decision input hint
- selected profile and attribution reason

## 2.4 Domain-first at the surface, primitive-first underneath
사용자에게 보이는 제품 표면은 **도메인 프로필 중심**이어야 한다.
내부 엔진은 **재사용 가능한 reasoning primitive 중심**이어야 한다.

즉:
- 바깥 설명: secure update, auth/session, secure boot, crypto assurance, recovery integrity
- 내부 구조: result-use, enforcement, state lifecycle, decision input hints, bounded propagation, profile attribution

## 2.5 LLM is delayed on purpose
LLM은 지금 탐지기가 아니다.
나중에 아래 역할만 맡는다.
- candidate interpretation
- scenario understanding
- specification mapping
- triage / prioritization
- checker synthesis

---

# 3. CLI-First Operational Contract

이 프로젝트는 **CLI 우선**으로 설계한다.

## 3.1 공식 인터페이스
사용자와 AI Agent가 사용하는 공식 인터페이스는 `check_me` 명령 하나다.

허용되는 공식 사용 예:
- `check_me index ...`
- `check_me security-model ...`
- `check_me model --mode code ...`
- `check_me model --mode scenario ...`
- `check_me stats ...`
- `check_me validate ...`
- `check_me list-profiles`
- `check_me spec-check ...`

## 3.2 비공식/비권장 인터페이스
다음은 내부 구현에는 있을 수 있지만, 공식 워크플로우로 문서화하지 않는다.
- `python -m check_me ...`
- 특정 모듈 직접 실행
- ad-hoc one-liner Python script
- 내부 JSON을 직접 조합해서 기능을 우회 실행하는 방식

## 3.3 새 기능 추가 원칙
앞으로 추가되는 주요 기능은 먼저 CLI subcommand 또는 CLI option으로 노출한다.

예:
- fixture 검증 기능이 필요하면 `check_me fixture-check ...`
- profile 패키지 검증이 필요하면 `check_me profile-check ...`
- 테스트 통합 기능이 필요하면 `check_me test ...`

아직 구현되지 않은 CLI는 문서에 확정 기능처럼 쓰지 않는다.

## 3.4 CLI 안정성 원칙
- 동일 입력에 대해 구조적으로 동일한 출력
- exit code 일관성
- machine-readable JSON artifact 우선
- human-readable summary는 보조
- validate / stats / model 결과는 서로 모순되지 않아야 함

---

# 4. 제품 범위

## 4.1 지금 해야 하는 것
- compile-aware parsing
- deterministic indexing
- direct call graph 구축
- shared artifacts 생성
- code mode candidate generation
- scenario mode candidate generation
- domain profile 기반 scenario execution
- evidence preserving
- stats / validate / fixture / tests 정합성 유지
- 위 기능들을 CLI로 일관되게 실행 가능하게 유지

## 4.2 지금 주장하면 안 되는 것
- full taint proof
- execution path proof
- path feasibility proof
- CFG/CPG/SSA 기반 reasoning
- symbolic execution
- full protocol verification
- complete auth protocol soundness
- complete concurrency correctness
- complete crypto correctness
- final CWE correctness
- automatic mitigation correctness

---

# 5. 제품 구조

`check_me`는 두 개의 peer mode를 가진다.

- **Code Mode**: 코드 중심 구조 후보 생성
- **Scenario Mode**: 보안 명세 위반 중심 구조 후보 생성

두 모드는 shared deterministic foundation 위에서 동작한다.
모든 주요 기능은 최종적으로 `check_me` CLI를 통해 호출 가능해야 한다.

---

# 6. Shared Deterministic Foundation

## 6.1 입력
- source tree
- compile_commands.json
- registry / rule data
- optional scenario spec
- optional scenario profiles

## 6.2 shared core responsibilities
- compile_commands ingestion
- parser backend selection (`clang_json` 우선, `libclang` 보조)
- deterministic indexing
- persistent cache
- function extraction
- direct call graph
- function summaries
- structural reasoning primitives
- stats
- validation

## 6.3 shared artifacts
최소한 아래 아티팩트는 shared 또는 mode별 기반이 된다.
- `symbols.json`
- `files.json`
- `call_graph.json`
- `function_summaries.json`
- `stats.json`
- validation output

## 6.4 구현 원칙
- compile_commands.json 없으면 heuristic fallback을 남발하지 않는다.
- parser backend 차이는 artifact metadata에 남긴다.
- cache는 backend/mtime/compile hash에 민감해야 한다.
- deterministic ordering을 강제한다.
- stateful randomness를 쓰지 않는다.
- foundation 결과는 CLI로 재현 가능해야 한다.

---

# 7. Code Mode

## 7.1 Code Mode가 답하려는 질문
- dangerous API가 있는가
- source와 sink가 구조적으로 가까운가
- sanitizer가 보이는가
- bounded propagation이 후보의 신뢰도/상태를 바꾸는가
- 코드 수준에서 review할 만한 structural security concern이 있는가

## 7.2 Code Mode의 현재 철학
Code Mode는 vulnerability detector가 아니다.
Code Mode는 코드 중심 structural candidate generator다.

## 7.3 핵심 구성요소
- source/sink/sanitizer matcher
- bounded propagation
- code candidate generator
- candidate state refinement
- profile-unaware core candidate logic

## 7.4 Code Mode 주요 아티팩트
- `source_sink_matches.json`
- `flow_seeds.json`
- `propagation_paths.json`
- `code_candidates.json`

## 7.5 Candidate states
가능하면 아래 상태를 유지한다.
- ACTIVE
- FILTERED
- BOUNDARY_LIMITED
- SANITIZER_AFFECTED

## 7.6 Code Mode 제약
- direct calls 우선
- bounded depth 우선
- unresolved / indirect는 explicit boundary로 남긴다
- sanitizer effect는 과대평가하지 않는다
- source→sink는 구조적 concern이지 proof가 아니다

## 7.7 Code Mode 향후 심화 방향
후속 심화 순서:
1. points-to / alias-lite
2. indirect call boundary refinement
3. stronger propagation summaries
4. selected taint-like refinement
5. constraint-aware but bounded filtering

단, 이는 full taint engine이나 symbolic execution을 바로 뜻하지 않는다.

## 7.8 Code Mode CLI 원칙
Code Mode의 모든 일반 사용 흐름은 아래처럼 CLI로 닫혀야 한다.
- `check_me index ...`
- `check_me security-model ...`
- `check_me model --mode code ...`
- `check_me stats ...`
- `check_me validate ...`

직접 Python API 호출 예시는 내부 개발 참고용일 수는 있어도, 공식 사용법의 중심에 두지 않는다.

---

# 8. Scenario Mode

## 8.1 Scenario Mode가 답하려는 질문
- 필요한 check가 존재하는가
- 그 check의 결과가 실제 enforcement에 쓰이는 흔적이 있는가
- 필요한 auth/verified/trusted state가 보이는가
- 민감 action 전에 요구된 precondition이 구조적으로 보이는가
- stale state, replay, weak version policy, rollback risk, missing self-test 같은 구조적 문제가 보이는가

## 8.2 Scenario Mode의 핵심 정의
Scenario Mode는 generic security zoo가 아니다.
Scenario Mode는 **security-specification violation candidate engine**이다.

즉 이 모드는 아래를 본다.
- check presence
- result use
- enforcement linkage
- required state
- trusted/untrusted decision inputs
- stale state reuse
- domain-profile relevance

## 8.3 Scenario Mode 출력물
- `scenario_candidates.json`
- `guard_evidence.json`
- `profile_summary.json` (profile-aware 실행 시)
- profile-aware fields in `stats.json`

## 8.4 Scenario Mode claim rule
Scenario Mode는 execution path를 증명하지 않는다.
대신 다음 표현을 선호한다.
- structurally identified
- structurally suggested
- not clearly shown to gate the action
- structural evidence of missing enforcement

## 8.5 Scenario Mode CLI 원칙
Scenario Mode의 공식 실행 경로도 CLI로 통일한다.

예:
- `check_me list-profiles`
- `check_me model --mode scenario --profile secure_update_install_integrity ...`
- `check_me model --mode scenario --scenario-spec ./my_scenario.yaml ...`
- `check_me spec-check --scenario-spec ./my_scenario.yaml`
- `check_me stats ...`
- `check_me validate ...`

향후 profile 검사, fixture 실행, scenario pack 검증도 가능하면 CLI 하위 명령으로 노출한다.

---

# 9. Domain Profiles

도메인 프로필은 Scenario Mode의 주된 제품 표면이다.

## 9.1 Stable profiles

### `secure_update_install_integrity`
핵심 질문:
- verify-before-update/install/use가 있는가
- verification result가 write/install/activate를 gate하는가
- stale trusted metadata reuse 위험이 보이는가
- rollback / version policy가 구조적으로 약해 보이는가

대표 candidate families:
- `UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK`
- `ACTION_BEFORE_REQUIRED_CHECK`
- `RESULT_NOT_ENFORCED`
- `VERSION_POLICY_WEAK_OR_INCONSISTENT`
- `ROLLBACK_PROTECTION_MISSING_OR_WEAK`

### `auth_session_replay_state`
핵심 질문:
- privileged action 전에 verified/authenticated state가 필요한가
- 그 state가 실제로 gate에 쓰이는가
- replay/persistence/stale state reuse 위험이 구조적으로 보이는가

대표 candidate families:
- `PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE`
- `STATE_PERSISTENCE_REPLAY_RISK`
- `RESULT_NOT_ENFORCED`

## 9.2 Experimental profiles

### `secure_boot_chain`
핵심 질문:
- verify-before-execute 구조가 보이는가
- partition-level verify omission이 보이는가
- chain-of-trust gap indicator가 보이는가

### `crypto_operational_assurance`
핵심 질문:
- self-test-before-use가 보이는가
- secret verification context에서 narrow compare concern이 보이는가
- countermeasure setup missing이 구조적으로 보이는가

### `error_recovery_state_integrity`
핵심 질문:
- abnormal condition handling이 보이는가
- failure cleanup이 보이는가
- stale state reuse after failure/recovery가 보이는가

## 9.3 Profile metadata
각 profile은 적어도 다음 메타데이터를 가져야 한다.
- profile_id
- maturity: stable | experimental
- intended domain
- enabled candidate families
- primary structural artifacts used

## 9.4 Profile overlap
하나의 candidate는 여러 profile과 관련될 수 있다.
이 경우:
- primary profile 하나를 정한다
- shared / secondary relevance를 명시한다
- silent duplication은 피한다
- tie-breaking은 deterministic해야 한다

---

# 10. 실제 타깃 시나리오 클래스

`check_me`는 아래와 같은 구조적으로 식별 가능한 시나리오들에 가까워져야 한다.

- update failure 후 stale trusted header/state reuse
- crypto image update without authenticity verification
- verification called but not enforced before write/install/activate
- incomplete/finalization-weak update acceptance
- auth/session state replay or persistence risk
- self-test-before-crypto-use missing
- version/build-date / rollback policy weakness
- abnormal condition / recovery state integrity weakness
- secure boot chain / verify-before-execute expectations

중요:
이 문장은 “이미 완전히 탐지한다”는 뜻이 아니다.
이것은 설계 앵커(anchor)다.
fixture, profile, candidate family, artifact는 이 시나리오들을 향해 정렬되어야 한다.

---

# 11. Structural Reasoning Primitives

내부적으로 재사용할 핵심 primitive는 다음과 같다.

- result-use links
- enforcement links
- action/guard mapping
- state summaries
- state lifecycle entries
- decision input hints
- bounded propagation summaries
- profile attribution metadata

각 primitive는 다음 특성을 가져야 한다.
- deterministic
- compact
- machine-readable
- confidence bounded
- heuristic 여부 표시 가능

---

# 12. Confidence / Claim Policy

## 12.1 confidence 의미
confidence는 exploitability probability가 아니다.
confidence는 **구조적 증거 강도**다.

## 12.2 허용 구간
현재는 low ~ moderate 범위를 넘기지 않는 것이 기본이다.
고신뢰(high confidence) 표현은 CFG/feasibility/semantic reasoning 없이는 쓰지 않는다.

## 12.3 must-not-claim 목록
다음은 현재 금지한다.
- execution path verified
- vulnerability proven
- exploitable confirmed
- crypto broken
- race detected
- deadlock detected
- timing attack confirmed

---

# 13. Validation / Testing Policy

## 13.1 validation 목표
validate는 단순 존재 확인이 아니라, 아래를 본다.
- artifact schema validity
- profile metadata consistency
- deterministic ordering
- no invalid profile ids
- no candidate mislabeled as finding/vulnerability/CWE

## 13.2 testing 목표
테스트는 최소한 아래를 포함한다.
- artifact generation
- schema validity
- profile overlap determinism
- backward compatibility
- target scenario fixture integration
- CLI behavior consistency

## 13.3 CLI-based verification principle
가능한 한 검증과 점검은 `check_me` CLI를 통해 수행한다.

장기적으로 이상적인 형태:
- `check_me validate ...`
- `check_me stats ...`
- `check_me spec-check ...`
- `check_me list-profiles`
- `check_me fixture-check ...` *(future if needed)*
- `check_me test ...` *(future if needed)*

즉, 내부 테스트 프레임워크가 있더라도 사용자/에이전트 워크플로우는 CLI 중심으로 수렴시킨다.

---

# 14. LLM Role (Future)

LLM은 primary detector가 아니다.
후속 phase에서 아래 역할을 맡는다.
- candidate interpretation
- scenario reasoning
- specification mapping
- triage/prioritization
- checker synthesis

LLM을 붙이기 위한 전제 조건:
- profile-driven scenario execution 안정화
- target scenario pack 확장
- stronger structural artifacts
- stats/validate consistency
- docs/product truth consistency

이 전제 없이 LLM을 붙이면 heuristic noise를 설명만 그럴듯하게 만들 위험이 있다.

---

# 15. 에이전트 작업 규칙

AI Agent는 앞으로 작업할 때 아래를 반드시 따른다.

1. README를 길게 만들지 말 것
2. 상세 설계는 PLAN.md를 source of truth로 볼 것
3. 새 phase 문서를 무한정 늘리지 말 것
4. 새 기능을 넣을 때 공식 CLI 진입점부터 생각할 것
5. profile/domain surface와 internal primitive를 혼동하지 말 것
6. 현재 구현보다 강한 claim을 문서에 쓰지 말 것
7. candidate와 finding을 혼동하지 말 것
8. 테스트/validate/stats/doc이 서로 모순되지 않게 할 것
9. 외부 검색이 없다는 전제로, 필요한 설계 원칙을 문서 안에 충분히 적을 것
10. 구현이 바뀌면 README보다 먼저 PLAN의 철학/구조를 점검할 것

---

# 16. 앞으로의 우선순위

현재 우선순위는 다음과 같다.

1. CLI-first consistency
2. profile-driven scenario execution 안정화
3. target scenario pack 강화
4. code mode refinement (필요 시)
5. deeper structural reasoning
6. 그 다음에야 LLM interpretation layer

즉, **다음 큰 점프는 LLM이 아니라 더 강한 deterministic substrate**다.

---

# 17. 문서 관리 원칙

- README: 짧고 핵심만
- PLAN.md: 설계 기준서
- 추가 문서는 정말 필요한 completion/proof용만
- phase가 끝날 때마다 README를 비대하게 만들지 않는다
- 문서가 코드보다 앞서 과장하지 않도록 항상 점검한다

---

# 18. 한 줄 결론

`check_me`는 **C/C++-first, CLI-first, deterministic-first** 보안 후보 생성 도구다.

- Code Mode는 코드 중심 구조 후보를 생성한다.
- Scenario Mode는 domain profile 기반 보안 명세 위반 후보를 생성한다.
- LLM은 나중에 해석기로 붙는다.
- 지금 가장 중요한 것은 강한 deterministic substrate와 일관된 CLI 운영이다.
