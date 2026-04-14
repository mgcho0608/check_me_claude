# check_me

`check_me`는 **C/C++ 우선** 정적 보안 분석 도구다.
목표는 취약점을 바로 확정하는 것이 아니라, **검토할 가치가 있는 보안 후보(candidates)** 를 **결정론적(deterministic)** 으로 생성하는 것이다.

## 핵심 의도

`check_me`는 두 가지 질문을 다룬다.

### Code Mode
코드 자체에 묻는다.

- 위험한 API를 쓰는가
- source 근처에 sink가 있는가
- sanitizer 흔적이 있는가
- bounded propagation으로 봤을 때 후보를 더 좁힐 수 있는가

### Scenario Mode
시스템 보안 명세에 묻는다.

- 민감 동작 전에 필요한 검증이 있는가
- 체크는 존재하지만 실제 enforcement에 쓰이는가
- 필요한 상태(`*_verified`, `*_authenticated` 등)가 없이 privileged path가 열리는가
- 업데이트/부트/복구 과정에서 보안 약속이 구조적으로 깨질 수 있는가

## 이 도구가 하는 일

- 결정론적 후보 생성
- 구조적 증거 수집
- 프로필 기반 시나리오 분석
- 리뷰와 triage를 위한 artifact 생성

## 이 도구가 아직 하지 않는 일

- 취약점 확정
- CFG/CPG/SSA 기반 실행 경로 증명
- full taint propagation
- path feasibility 증명
- LLM 기반 탐지
- CWE 확정 매핑
- mitigation 자동 생성

즉, `check_me`는 **보안 후보를 정리해서 보여주는 엔진**이지, 아직 **최종 판정기**는 아니다.

## CLI 원칙

사용자와 에이전트가 사용하는 공식 진입점은 **항상 `check_me` CLI**다.

- 검증, 분석, 통계, 프로필 조회는 모두 `check_me ...` 형식으로 수행한다.
- 특정 내부 파이썬 모듈을 직접 실행하는 방식은 공식 사용법으로 두지 않는다.
- 앞으로 새 기능이 생겨도 먼저 CLI 하위 명령으로 노출하는 것을 원칙으로 한다.

## 기본 사용법

### 1. 공통 substrate 생성
```bash
check_me index \
  --dir-path ./project \
  --compile-commands compile_commands.json

check_me security-model \
  --dir-path ./project \
  --compile-commands compile_commands.json \
  --registry-path rules/c_cpp_registry.yaml
```

### 2. Code Mode 실행
```bash
check_me model --mode code \
  --dir-path ./project \
  --compile-commands compile_commands.json
```

### 3. Scenario Mode 실행
```bash
check_me list-profiles

check_me model --mode scenario \
  --profile secure_update_install_integrity \
  --dir-path ./project \
  --compile-commands compile_commands.json
```

### 4. Custom scenario spec 실행
```bash
check_me model --mode scenario \
  --scenario-spec ./my_scenario.yaml \
  --dir-path ./project \
  --compile-commands compile_commands.json
```

### 5. 결과 확인
```bash
check_me stats --dir-path ./project
check_me validate --dir-path ./project
```

## 내장 Scenario Profiles

### Stable
- `secure_update_install_integrity`
- `auth_session_replay_state`

### Experimental
- `secure_boot_chain`
- `crypto_operational_assurance`
- `error_recovery_state_integrity`

프로필은 단순 라벨이 아니라, **어떤 후보 패밀리를 우선적으로 활성화하고 어떤 시나리오를 중심으로 볼지**를 정하는 입력이다.

## 주요 출력물

### Code Mode
- `source_sink_matches.json`
- `flow_seeds.json`
- `propagation_paths.json`
- `code_candidates.json`

### Scenario Mode
- `scenario_candidates.json`
- `guard_evidence.json`
- `profile_summary.json` *(있다면)*

### Shared
- `stats.json`
- `symbols.json`
- `call_graph.json`
- `files.json`
- `function_summaries.json`

## 현재 철학

- 탐지는 결정론적으로
- LLM은 나중에 해석기로
- Scenario mode는 security-specification violation 중심으로
- 문서 표면은 domain-profile 중심으로
- 내부 엔진은 reusable primitive 중심으로
- 공식 사용 경로는 CLI 하나로 통일

## 한 줄 정리

`check_me`는 **C/C++ 코드와 시스템 보안 명세를 대상으로, 리뷰 가능한 보안 후보를 결정론적으로 생성하는 CLI 중심 도구**다.
