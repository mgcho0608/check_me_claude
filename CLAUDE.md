# Claude Agent 행동규칙 — check_me

## 세션 시작 시 (필수)

1. `README.md`를 읽는다 — 제품 정의와 CLI 인터페이스 파악
2. `PLAN.md`를 읽는다 — 설계 기준, 현재 우선순위, 에이전트 작업 규칙 파악
3. 현재 구현 상태와 문서 내용이 일치하는지 확인한다

## 세션 종료 시 (필수)

1. 이번 작업으로 구현이 바뀐 부분이 있으면 `PLAN.md`를 먼저 점검·갱신한다
2. `README.md`는 짧게 유지한다 — 핵심만, 과장 없이
3. 문서가 실제 구현보다 앞서 강한 claim을 하고 있지 않은지 확인한다

## 핵심 작업 규칙 (PLAN.md §15 요약)

- README는 짧게 유지 / 상세 설계는 PLAN.md가 source of truth
- 새 기능은 반드시 CLI subcommand로 먼저 노출
- profile/domain surface와 internal primitive를 혼동하지 않는다
- candidate와 finding(vulnerability)을 혼동하지 않는다
- 현재 구현보다 강한 claim을 문서에 쓰지 않는다
- validate / stats / doc이 서로 모순되지 않게 유지한다

## 현재 개발 우선순위 (PLAN.md §16)

1. CLI-first consistency
2. profile-driven scenario execution 안정화
3. target scenario pack 강화
4. code mode refinement
5. deeper structural reasoning
6. (그 다음에야) LLM interpretation layer

## 프로젝트 경로

- Repo: `/c/Users/mgcho/check_me_claude`
- 문서: `README.md`, `PLAN.md`
- Remote: `https://github.com/mgcho0608/check_me_claude`
