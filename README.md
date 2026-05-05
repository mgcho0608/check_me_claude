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
- LLM provider 설정 (Step 2/3/4): [docs/LLM_CONFIG.md](./docs/LLM_CONFIG.md)
- JSON schemas: [schemas/](./schemas/)
- 데이터셋: [datasets/](./datasets/)

## 현재 상태

**4-step 파이프라인 모두 구현·검증 완료** (3 dataset 기준).
pytest 320+개 모두 통과. 자세한 상태는
[PLAN.md §Appendix A](./PLAN.md#appendix-a-current-pipeline-state) 참고.

| Step | 구현 | 모듈 | LLM | 결정론 / 합성 분업 |
|---|---|---|---|---|
| Step 1 | ✅ | `src/check_me/step1/` | 없음 | 100% 결정론 (libclang AST + regex baseline) |
| Step 2 | ✅ | `src/check_me/step2/` | miner + verifier | chunked miner (lossless propagation), 별개 LLM 인스턴스, anchoring 차단 |
| Step 3 | ✅ | `src/check_me/step3/` | per-IR synthesis | N=2 hybrid retrieval (call edges + shared global state) — LLM 자유 선택 금지 |
| Step 4 | ✅ | `src/check_me/step4/` | single-call scenario synth | IR weaving — 시나리오 = exploit_chain + ≥1 sink |

각 단계는 sequential 호출 + per-call 실패 fallback + 재시도 패스로
provider rate-limit / transient 장애 안에서 안정 동작.

### 3 dataset 종합 결과 (gold 대비, 2026-05-05 시점)

| Dataset | Step 1→4 결과 | 비고 |
|---|---|---|
| **libssh** CVE-2018-10933 | ✅ Gold AS-001 (auth_bypass / privilege_bypass / high) 정확 회수 | multi-IR weave (IR-028 → IR-026 → IR-039) 작동 |
| **dnsmasq** CVE-2017-14491 | ✅ Gold AS-001+002 (memory_write / memory_corruption) 정확 회수 (UDP/TCP 둘 다) | retrieval file-attribution + deeper-sink prompt fix 적용 |
| **contiki-ng** CVE-2021-21281 | ⚠️ Step 3 IR-047이 gold sink (uip_process / state_corruption) 정확 회수, Step 4가 78 IRs 중 15개만 시나리오로 변환해 IR-047 누락 | substrate / IR 차원에서는 보존 (audit 가능). chunked Step 4가 follow-up fix 후보 |

자세한 산출물은 [`out/<project>-<cve>/`](./out/) 참조 (substrate.json /
entrypoints.json / evidence_irs.json / attack_scenarios.json).

## 한 줄 결론

Check Me는 **하나의 일관된 4단계 아키텍처 + 외부 grounded project-level 데이터셋 + 정직한 평가** 위에서 동작하는 보안 분석기다.
