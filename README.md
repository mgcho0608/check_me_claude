# Aegis Inspect

**Aegis Inspect**는 C/C++ 코드베이스를 대상으로, 4단계 파이프라인을 통해 exploit 가능한 공격 시나리오를 도출하는 보안 분석 도구다.

## 핵심 방향

```
Step 1: 결정론적 substrate 구축          (rule-based, LLM 없음)
Step 2: LLM entrypoint mining + 검증    (proposer / verifier 분리)
Step 3: LLM Evidence IR 구성            (N-hop retrieval, 결정론적)
Step 4: LLM 공격 시나리오 도출           (exploit chain + sink 필수)
```

### 멘탈 모델: Points → Lines → Shapes

- Step 1은 선을 구성할 수 있는 **점**들을 찾는다
- Step 2는 선의 시작점인 **entry point**를 추가하고 검증한다
- Step 3은 점들을 이어 실행 path의 **선(Evidence IR)** 을 구성한다
- Step 4는 선들을 엮어 공격 시나리오라는 **도형**을 완성한다

Step 1 substrate가 정밀할수록 Step 2~3에서 LLM이 봐야 하는 코드량이 기하급수적으로 줄어든다.

## 주요 산출물

| Step | 산출물 |
|------|--------|
| Step 1 | call graph, data/control flow, guard/enforcement, trust boundary, config trigger, callback registration, evidence anchor |
| Step 2 | verified entrypoints (substrate에 누적), quarantine bucket |
| Step 3 | `EvidenceIR` — 실행 경로별 path + conditions + evidence anchors |
| Step 4 | `AttackScenario` — exploit chain + sink + verdict |

## 현재 상태

구현 전 (Stage 0 준비 단계). 구 설계(`check_me` v0.1.0)는 `archive/v0-old-design` 브랜치에 보존.

설계 기준: `PLAN.md`
