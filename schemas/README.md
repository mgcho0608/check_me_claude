# Schemas

이 디렉토리는 4-step gold artifact의 JSON schema를 담는다. 모든 schema는 versioned이며, gold 파일은 반드시 `schema_version` 필드를 포함한다.

## 파일

| Schema | 파일 | 용도 |
|---|---|---|
| Substrate (Step 1) | `substrate.v1.json` | call graph, flows, guards, trust boundaries, triggers, callbacks, anchors |
| Entrypoints (Step 2) | `entrypoints.v1.json` | verified entrypoints + quarantined |
| Evidence IR (Step 3) | `evidence_irs.v1.json` | execution-path별 cluster |
| Attack Scenarios (Step 4) | `attack_scenarios.v1.json` | exploit chain + sink |

## Enum 정책 (모든 schema 공통)

- 모든 분류 enum은 `unknown` 멤버를 항상 포함한다.
- 새 케이스 만나면 `unknown` + free-text note로 기록.
- `unknown` 빈도가 높아지면 schema version up + enum 추가.

## Schema version 룰

- breaking change → major version up (v1 → v2)
- 새 optional 필드 / 새 enum value → minor (현 단계에선 v1.x 식 추가 사용 X. v2로 직행)
- gold 파일은 자기 schema_version을 명시 (`"schema_version": "v1"`)

## 최소주의 원칙

지금 schema는 **꼭 필요한 것만**. 복잡도가 IR 표현력을 압도하지 않도록 한다. 케이스가 늘어나면서 부족한 부분을 점진 추가.
