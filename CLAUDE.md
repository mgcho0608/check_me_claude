# Claude Agent 행동규칙 — Aegis Inspect

## 세션 시작 시 (필수)

1. `README.md`를 읽는다 — 제품 정의와 파이프라인 파악
2. `PLAN.md`를 읽는다 — 설계 기준, 현재 구현 상태, 에이전트 작업 규칙 파악
3. 현재 구현 상태와 문서 내용이 일치하는지 확인한다

## 세션 종료 시 (필수)

1. 이번 작업으로 구현이 바뀐 부분이 있으면 `PLAN.md`를 먼저 점검·갱신한다
2. `README.md`는 짧게 유지한다 — 핵심만, 과장 없이
3. 문서가 실제 구현보다 앞서 강한 claim을 하고 있지 않은지 확인한다

## 핵심 작업 규칙

- README는 짧게 유지 / 상세 설계는 PLAN.md가 source of truth
- Step 1 구현에 LLM을 쓰지 않는다
- substrate 항목을 fact / heuristic으로 형식 분리하지 않는다
- downstream은 Step 1 substrate가 100% 정확하지 않을 수 있음을 인지하고 동작한다
- Step 2에서 proposer의 reasoning을 verifier에게 공개하지 않는다
- Evidence IR마다 entry point가 명시되어 있는지 확인한다
- AttackScenario에 exploit chain과 최소 1개 sink가 명시되어 있는지 확인한다
- 데이터셋은 전체 코드베이스 클론 후 평가에 모두 사용한다
- dataset ground truth는 반드시 외부 출처(CVE, 연구 논문 등)에서 trace 가능해야 한다
- LLM 생성 synthetic data를 평가 근거로 쓰지 않는다
- 현재 구현보다 강한 claim을 문서에 쓰지 않는다

## 현재 개발 우선순위 (PLAN.md §6)

1. Stage 0 — 결정론적 Substrate 구축 (Step 1 구현)
2. Stage 1 — Entrypoint Mining + Evidence IR (Step 2, 3 구현)
3. Stage 2 — 공격 시나리오 생성 (Step 4 구현)
4. Stage 3 — 전체 파이프라인 평가

## 프로젝트 경로

- Repo: `/home/user/check_me_claude`
- 문서: `README.md`, `PLAN.md`
- Remote: `https://github.com/mgcho0608/check_me_claude`
