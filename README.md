# Check Me

C/C++ project-level codebase에서 **exploit 가능한 공격 시나리오**를 도출하는 4단계 보안 분석 프레임워크.

## 한 줄 정의

> **결정론적 substrate 추출 → LLM entrypoint mining + 검증 → LLM Evidence IR → LLM 공격 시나리오** — project-level codebase에 대해 외부 grounded 데이터셋으로 평가.

## Mental Model: Points → Lines → Shapes

```
Step 1: 점(point)을 추출    — rule-based, 결정론적
Step 2: 선의 시작점 추가    — LLM proposer + verifier
Step 3: 점들을 이어 선 구성 — Evidence IR
Step 4: 선들을 엮어 도형     — 공격 시나리오
```

- 선의 시작점은 반드시 entry point.
- 도형은 선 하나일 수도, 같은 선을 여러 번 다른 순서로 쓸 수도 있음.
- **Step 1이 정밀할수록 Step 2-3에서 LLM이 봐야 하는 코드량이 기하급수적으로 줄어듦.**

## 산출물

- **Substrate** (Step 1): call graph, data/control flow, guard/enforcement, trust boundaries, config/mode/command triggers, callback registrations, evidence anchors
- **Verified Entrypoints** (Step 2): substrate에 누적되는 검증된 runtime entry points + quarantine bucket
- **Evidence IR** (Step 3): execution-path별 cluster, 모든 claim에 file:line provenance
- **Attack Scenario** (Step 4): exploit chain + ≥ 1 sink

## 사용 위치

- 설계 기준서: [PLAN.md](./PLAN.md) — source of truth
- 에이전트 행동규칙: [CLAUDE.md](./CLAUDE.md)
- 데이터셋 라벨링 SOP: [datasets/WORKFLOW.md](./datasets/WORKFLOW.md)
- JSON schemas: [schemas/](./schemas/)
- 데이터셋: [datasets/](./datasets/)

## 현재 상태

**Stage 0 (결정론적 substrate 구축) 종료.** 7개 카테고리 추출기 + regex baseline 비교 모두 구현, 4/4 exit criteria 충족, 3개 project-level CVE 데이터셋 (contiki-ng, libssh, dnsmasq), pytest 157개 모두 통과. 자세한 상태는 [PLAN.md §Appendix A](./PLAN.md#appendix-a-current-pipeline-state) 참고.

다음 단계는 **Stage 1**: Step 2 (LLM entrypoint mining + verification) + Step 3 (Evidence IR).

## 한 줄 결론

Check Me는 **하나의 일관된 4단계 아키텍처 + 외부 grounded project-level 데이터셋 + 정직한 평가** 위에서 동작하는 보안 분석기다.
