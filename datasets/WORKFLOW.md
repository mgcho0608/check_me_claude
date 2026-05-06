# Dataset Construction Workflow

이 문서는 데이터셋 1건을 만들 때 따라야 하는 표준 절차다. 모든 데이터셋은 이 절차를 동일하게 따라야 한다 — 데이터셋 간 비교 가능성을 확보하기 위함.

## 디렉토리 구조

```
datasets/<project>-<cve>/
  metadata.json
  source/                    # vulnerable commit으로 클론한 repo 통째로 (vendored)
  gold/
    substrate.json           # Step 1 ground truth
    entrypoints.json         # Step 2 ground truth (kept + quarantined)
    evidence_irs.json        # Step 3 ground truth
    attack_scenarios.json    # Step 4 ground truth
  notes.md                   # 라벨링 과정 기록 + self-check 로그
```

## 절차

### 1. Authoritative source 수집
- CVE 공식 entry (NVD / CVE.org / GHSA)
- Vendor advisory / 연구 논문 / 보안 블로그 write-up
- Fix commit 및 그 parent commit 확인
- 모두 `metadata.json` 의 `authoritative_sources` 에 URL로 기록

### 2. Vulnerable repo 클론
```bash
mkdir -p datasets/<project>-<cve>
cd datasets/<project>-<cve>
git clone <repo_url> source
cd source
git checkout <vulnerable_commit_sha>      # fix commit의 parent
rm -rf .git                               # vendored 상태로 우리 repo에 들어감 (선택)
```
- `vulnerable_commit` 은 **fix commit의 직전 commit**.
- `.git` 제거 여부는 사이즈와 추적 필요성에 따라 선택. 기본은 제거 (vendored snapshot).

### 3. metadata.json 작성
필수 필드:
```
project, cve, repo_url, vulnerable_commit, fix_commit,
build_commands, vulnerability_summary, attack_entry_modes,
key_files, authoritative_sources, self_contained: true
```
build_commands는 compile_commands.json 생성까지 포함해야 한다 (Step 1 Clang AST 분석을 위해).

### 4. Patch diff 분석
- `fix_commit` 과 `vulnerable_commit` 을 받아 변경된 함수, 추가된 guard, 수정된 state variable 정리.
- 각 변경 사항이 `source/` 안에서 resolve되는지 확인 (file:line이 클론된 트리에 존재).

### 5. 4-step gold 작성 (순서 고정)
**Step 1 → Step 4 순서로 작성**. 각 단계가 다음 단계의 입력이므로 역순 안 됨.

#### gold/substrate.json
취약점과 직접 관련된 substrate facts만 포함 (전체 codebase substrate가 아니라, 평가에 필요한 부분만 ground truth로). 7 카테고리 모두 cover.

#### gold/entrypoints.json
- `kept`: 검증된 runtime entrypoint들. supporting substrate edges 명시.
- `quarantined`: 낮은 신뢰도로 제거된 candidates. 사유 명시.

#### gold/evidence_irs.json
취약 path를 cover하는 IR cluster들. 각 IR에:
- `entrypoint` 필수
- 모든 path node에 file:line
- `confidence` + `uncertainty` 필수

#### gold/attack_scenarios.json
각 scenario에:
- `exploit_chain` (Evidence IR id 시퀀스)
- `sink` (≥ 1, file:line 포함)
- `impact`, `verdict.exploitability`, `confidence`

### 6. Agent self-check (필수) — 두 단계 hand pass

라벨 작성 후 두 layer로 직접 (script 신뢰 금지) 수행하고 `notes.md` 에 결과 기록.

#### 6.1 Pass 1 — file:line + 의미 일치

- [ ] 모든 file:line 참조가 `source/` 안에서 resolve되며, 인용한 line text + enclosing function 둘 다 직접 본 코드와 일치하는가?
- [ ] 모든 claim이 patch diff / authoritative source / cloned code excerpt 중 하나로 backing되고, 그 backing이 실제로 해당 claim을 뒷받침하는지 한 번 더 읽어 확인했는가?
- [ ] enum 값이 `schemas/` 의 현재 schema_version과 일치하는가?
- [ ] 모든 AttackScenario에 exploit_chain + sink ≥ 1 이 있는가?
- [ ] 모든 EvidenceIR에 entry point가 있는가?
- [ ] Step 2 entrypoint에 supporting substrate edges 또는 quarantine 사유가 있는가?
- [ ] Step 1 substrate에 absence(없는 것)를 facts로 넣지 않았는가? (absence 의미는 IR `conditions.blocking` 또는 `guards_missing`에 둠)

#### 6.2 Pass 2 — Label-honesty (PLAN §4.6 #10)

라벨이 단지 "extractor와 매칭 잘 되게" 보이는 enum으로 force-fit되어 있지 않은지 별도 hand pass로 점검. 점수 inflate가 잘못된 라벨보다 더 나쁘다. corpus가 자라며 추가되는 stretch 패턴들:

- [ ] `kind: "function_table"` 은 **static array of function names** 만. main-loop 직접 호출이나 protothread/event-dispatch 매크로는 **function table 아님** → `unknown` + free-text.
- [ ] `kind: "compile_flag"` 은 **`-D<NAME>` 빌드 플래그** 만 (line: 0 관습). `#if` 블록 안 일반 C 라인은 `compile_flag` 행이 아님 → directive 라인을 `kind: "ifdef"` 로.
- [ ] `kind: "cli_argument"` 은 **CLI 파서 사이트** (예: `getopt` switch case) 만. CLI-gated 동작이 *발현되는* 라인은 cli_argument 행 아님 → `unknown` + free-text.
- [ ] `kind: "structural_artifact"` (evidence_anchors) 은 **top-level 구조적 사실** 만 (struct / typedef / enum / global / alias 매크로). 함수 본문 안 statement 라인은 `data_control_flow` 가 다룸 — evidence_anchors에 중복 기재 금지.
- [ ] `sink_type: "memory_read" | "memory_write"` 은 **그 라인이 정확히 그 동작을 수행할 때** 만. 라인이 *상태를 corrupt*시키고 실제 harmful read/write가 downstream에서 일어난다면 `sink_type: "state_corruption"` 으로 + `impact.description` 에 corruption→consequence 체인 명시.
- [ ] `trigger_type: "callback"` (entrypoints) 은 **callback 등록 메커니즘으로 설치된 함수** 만 (function-pointer assignment / function table / signal handler / constructor attribute). 일반 내부 호출은 callback trigger 아님 — entrypoint로 *유지*하고 싶다면 `trigger_type: "unknown"` + free-text.
- [ ] 모든 `unknown` enum 값에 free-text note가 동반되는가?

#### 6.3 notes.md 기록 규칙

- 두 pass 결과를 별도 audit log 섹션으로 기록 (예: "Audit log — round 1 (file:line + function)" 와 "Audit log — round 2 (label-honesty)"). 어떤 항목을 어떻게 잡고 어떻게 고쳤는지 한 줄씩 적는다.
- self-check 통과 / 미통과를 솔직히 기록. 통과 안 한 항목을 "OK"로 적지 않는다.

### 7. notes.md 기록
- 라벨링 과정에서 어려웠던 결정
- ambiguous한 케이스
- self-check 결과 (어느 항목 통과 / 어디서 보강했는지)
- 다음 데이터셋 작업 시 참고할 메모

### 8. Commit
- 단일 commit 권장. commit body에 self-check 결과 요약 포함.
- 메시지 형식 예: `dataset: <project>-<cve> initial gold` + body에 항목별 통과 여부.

## 절대 금지

- LLM에게 라벨을 시키고 결과만 채택하는 행위 (cross-reference + self-check 없이는 안 됨)
- patch diff만 읽고 라벨 작성 (cloned source에서 file:line resolve 확인 필수)
- 익명/유사 함수명 추측 (cloned source에서 실제 시그니처 확인)
- 단일 파일 또는 함수 snippet만 두고 데이터셋 등록
- LLM 합성 시나리오를 ground truth로 사용
