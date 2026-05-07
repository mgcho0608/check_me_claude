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

## CLI

`python -m check_me <subcommand>` — 6개 subcommand로 4-step 파이프라인 + 평가를 모두 커버.

| Subcommand | 역할 | LLM |
|---|---|---|
| `step1` | Substrate 추출 (Step 1) | 없음 |
| `regex-compare` | Clang vs regex 베이스라인 비교 (Stage 0 EC-1) | 없음 |
| `step2` | Entrypoint = 결정론적 synthetic 후보 + discovery miner + verifier | discovery miner + verifier |
| `step3` | Evidence IR 합성 (Step 3) | per-IR synthesis (N=2 hybrid retrieval) |
| `step4` | Attack scenario 합성 (Step 4) | chunked scenario synth (single-call when sink-bearing IR ≤ chunk size) |
| `eval` | Gold vs 산출물 4-step 매칭 + `eval_report.json` (Stage 3) | step3/step4에 LLM judge |

LLM-using subcommand들은 `CHECK_ME_LLM_*` env vars 또는 `.env`에서 provider/key/model을 읽음
(자세한 내용은 [docs/LLM_CONFIG.md](./docs/LLM_CONFIG.md)).

```bash
# Stage 0 — substrate
python -m check_me step1 \
  --src datasets/libssh-CVE-2018-10933/source \
  --project libssh --cve CVE-2018-10933 \
  --out out/libssh-CVE-2018-10933/substrate.json

# Stage 1 — entrypoints (--source 권장: verifier가 source 보고 판단)
python -m check_me step2 \
  --substrate out/libssh-CVE-2018-10933/substrate.json \
  --source datasets/libssh-CVE-2018-10933/source \
  --out out/libssh-CVE-2018-10933/entrypoints.json

# Stage 2 — evidence IRs + attack scenarios
python -m check_me step3 \
  --substrate out/libssh-CVE-2018-10933/substrate.json \
  --entrypoints out/libssh-CVE-2018-10933/entrypoints.json \
  --source datasets/libssh-CVE-2018-10933/source \
  --out out/libssh-CVE-2018-10933/evidence_irs.json
python -m check_me step4 \
  --evidence-irs out/libssh-CVE-2018-10933/evidence_irs.json \
  --source datasets/libssh-CVE-2018-10933/source \
  --out out/libssh-CVE-2018-10933/attack_scenarios.json

# Stage 3 — gold vs out 평가
python -m check_me eval \
  --gold datasets/libssh-CVE-2018-10933/gold \
  --out-dir out/libssh-CVE-2018-10933 \
  --report out/libssh-CVE-2018-10933/eval_report.json
```

`eval` subcommand는 모든 Stage 3 exit criteria (EC-1 \~ EC-4)를 통과하면 exit 0,
하나라도 실패하면 exit 1. `--skip-step3` / `--skip-step4`로 LLM-judge 패스를 끄고
deterministic Step 1 + Step 2 매칭만 빠르게 sanity check 가능.

## 현재 상태

**4-step 파이프라인 모두 구현 + 5개 active 데이터셋에서 정합성 검증.**
pytest 355개 모두 통과. 자세한 상태는
[PLAN.md §Appendix A](./PLAN.md#appendix-a-current-pipeline-state) 참고.

| Step | 구현 | 모듈 | LLM | 결정론 / 합성 분업 |
|---|---|---|---|---|
| Step 1 | ✅ | `src/check_me/step1/` | 없음 | 100% 결정론 (libclang AST + regex baseline) |
| Step 2 | ✅ | `src/check_me/step2/` | discovery miner + verifier | (a) substrate cuts (anchor + 1-hop closure + roots) → 결정론적 synthetic 후보. (b) discovery miner는 substrate에 없는 indirect-dispatch 등 새 entrypoint만 발굴. (c) verifier가 source-aware critique. anchoring 차단 (Rule 2b). |
| Step 3 | ✅ | `src/check_me/step3/` | per-IR synthesis | N=2 hybrid retrieval (call edges + shared global state) — LLM 자유 선택 금지 |
| Step 4 | ✅ | `src/check_me/step4/` | chunked scenario synth | sink-bearing IR을 fixed-size chunk로 split, 각 chunk 별 LLM 호출, 시나리오 dedup으로 merge. sink-bearing IR ≤ chunk size 일 때만 단일 호출. 시나리오 = exploit_chain + ≥1 sink. |

각 단계는 parallel 호출 (default 8 workers) + per-call 실패 fallback + 재시도 패스로
provider rate-limit / transient 장애 안에서 안정 동작. 모든 LLM-using
단계는 per-call 결과를 `<out_dir>/<step>_audit.jsonl` 로 stream-only
append — 진행 중에도 `tail -f` 가능, 프로세스 중단 시 완료된 작업
보존 (자동 resume은 미지원, 정상 종료 시 entrypoints.json /
evidence_irs.json / attack_scenarios.json은 기존대로 동작).

### Active datasets

5개 active 데이터셋, 1개 excluded (gold 라벨 없음). 자세한 내용은
[`datasets/registry.json`](./datasets/registry.json).

| Project | CVE | 상태 |
|---|---|---|
| **libssh** | CVE-2018-10933 | active (gold 4종 완비) |
| **dnsmasq** | CVE-2017-14491 | active (gold 4종 완비) |
| **lwip** | CVE-2020-22283 | active (gold 4종 완비) |
| **mbedtls** | CVE-2018-0488 | active (gold 4종 완비) |
| **sudo** | CVE-2021-3156 | active (gold 4종 완비) |
| _contiki-ng_ | _CVE-2021-21281_ | excluded — source 만, gold 없음 (codebase 규모로 신뢰성 있는 라벨링 곤란) |

자세한 산출물은 [`out/<project>-<cve>/`](./out/) 참조 (substrate.json /
entrypoints.json / evidence_irs.json / attack_scenarios.json).

## 한 줄 결론

Check Me는 **하나의 일관된 4단계 아키텍처 + 외부 grounded project-level 데이터셋 + 정직한 평가** 위에서 동작하는 보안 분석기다.
