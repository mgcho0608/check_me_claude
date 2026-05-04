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

### 6. Agent self-check (필수)
라벨 작성 후 반드시 수행하고 `notes.md` 에 결과 기록:

- [ ] 모든 file:line 참조가 `source/` 안에서 resolve되는가?
- [ ] 모든 claim이 patch diff / authoritative source / cloned code excerpt 중 하나로 backing되는가?
- [ ] enum 값이 `schemas/` 의 현재 schema_version과 일치하는가?
- [ ] 모든 AttackScenario에 exploit_chain + sink ≥ 1 가 있는가?
- [ ] 모든 EvidenceIR에 entry point가 있는가?
- [ ] Step 2 entrypoint에 supporting substrate edges 또는 quarantine 사유가 있는가?
- [ ] `unknown` enum이 사용된 경우 free-text note가 동반되는가?

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
