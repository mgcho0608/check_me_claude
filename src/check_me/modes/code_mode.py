"""Code Mode — 코드 중심 보안 후보 생성 (개선판).

개선 사항:
- call graph 기반 실제 source→sink 경로 추적
- 경로 상 sanitizer 존재 여부에 따른 state 정밀화
- primitives 활용 (result-use links로 confidence 보정)
- propagation_paths에 실제 경로 기록
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from check_me.config import LLMConfig


@dataclass
class ModeResult:
    candidate_count: int


# BFS 최대 탐색 깊이
_MAX_DEPTH = 5


class CodeMode:
    def __init__(
        self,
        dir_path: Path,
        compile_commands: Path | None,
        output_dir: Path,
        llm_config: LLMConfig,
    ) -> None:
        self.dir_path = dir_path
        self.compile_commands = compile_commands
        self.output_dir = output_dir
        self.llm_config = llm_config

    def run(self) -> ModeResult:
        symbols = self._load("symbols.json")
        call_graph = self._load("call_graph.json")
        security_model = self._load("security_model.json")
        primitives_list = self._load("primitives.json")

        # primitives index: function_id -> primitives dict
        primitives_idx = {p["function_id"]: p for p in primitives_list} \
            if isinstance(primitives_list, list) else {}

        # function name -> function id 역방향 인덱스
        functions = symbols.get("functions", []) if isinstance(symbols, dict) else []
        name_to_id: dict[str, str] = {f["name"]: f["id"] for f in functions}

        matches = self._match_source_sink(functions, security_model)
        seeds = self._build_flow_seeds(matches)
        paths = self._trace_paths(seeds, call_graph, name_to_id, security_model)
        candidates = self._generate_candidates(paths, primitives_idx)

        self._write("source_sink_matches.json", matches)
        self._write("flow_seeds.json", seeds)
        self._write("propagation_paths.json", paths)
        self._write("code_candidates.json", candidates)

        return ModeResult(candidate_count=len(candidates))

    # ------------------------------------------------------------------
    # Source / sink matching
    # ------------------------------------------------------------------

    def _match_source_sink(self, functions: list[dict], security_model: dict) -> list[dict]:
        rules = security_model.get("rules", []) if isinstance(security_model, dict) else []
        matches: list[dict] = []

        for rule in rules:
            sources = set(rule.get("sources", []))
            sinks = set(rule.get("sinks", []))
            sanitizers = set(rule.get("sanitizers", []))

            found_sources = [f for f in functions if f["name"] in sources]
            found_sinks = [f for f in functions if f["name"] in sinks]
            found_sanitizers = [f for f in functions if f["name"] in sanitizers]

            for src in found_sources:
                for sink in found_sinks:
                    matches.append({
                        "rule_id": rule.get("id", "unknown"),
                        "source": {"id": src["id"], "name": src["name"],
                                   "file": src["file"], "line": src["line"]},
                        "sink": {"id": sink["id"], "name": sink["name"],
                                 "file": sink["file"], "line": sink["line"]},
                        "sanitizers": [{"id": s["id"], "name": s["name"]}
                                       for s in found_sanitizers],
                    })

        return sorted(matches, key=lambda m: (m["rule_id"], m["source"]["id"], m["sink"]["id"]))

    # ------------------------------------------------------------------
    # Flow seeds
    # ------------------------------------------------------------------

    def _build_flow_seeds(self, matches: list[dict]) -> list[dict]:
        return [
            {
                "seed_id": f"seed_{i}",
                "rule_id": m["rule_id"],
                "source": m["source"],
                "sink": m["sink"],
                "sanitizers": m["sanitizers"],
            }
            for i, m in enumerate(matches)
        ]

    # ------------------------------------------------------------------
    # Path tracing (bounded BFS with sanitizer detection)
    # ------------------------------------------------------------------

    def _trace_paths(
        self,
        seeds: list[dict],
        call_graph: dict[str, list[str]],
        name_to_id: dict[str, str],
        security_model: dict,
    ) -> list[dict]:
        """
        각 seed에 대해 source에서 sink까지 call graph BFS를 수행한다.
        경로 상에 sanitizer가 있으면 sanitizer_on_path=True로 표시.
        """
        # 전체 sanitizer 이름 집합
        all_sanitizers: set[str] = set()
        for rule in (security_model.get("rules", []) if isinstance(security_model, dict) else []):
            all_sanitizers.update(rule.get("sanitizers", []))

        paths: list[dict] = []
        for seed in seeds:
            source_name = seed["source"]["name"]
            sink_name = seed["sink"]["name"]
            source_id = seed["source"]["id"]
            sink_id = seed["sink"]["id"]

            # BFS: source function id에서 도달 가능한 경로 탐색
            found_path, sanitizer_on_path, depth = self._bfs_path(
                source_id, sink_name, sink_id,
                call_graph, name_to_id, all_sanitizers,
            )

            paths.append({
                "seed_id": seed["seed_id"],
                "rule_id": seed["rule_id"],
                "source": seed["source"],
                "sink": seed["sink"],
                "path_found": found_path is not None,
                "path": found_path,
                "path_depth": len(found_path) if found_path else None,
                "sanitizer_on_path": sanitizer_on_path,
                "depth_limit": _MAX_DEPTH,
                "boundary": "direct_calls_only",
                "heuristic": True,
            })

        return sorted(paths, key=lambda p: p["seed_id"])

    def _bfs_path(
        self,
        start_id: str,
        sink_name: str,
        sink_id: str,
        call_graph: dict[str, list[str]],
        name_to_id: dict[str, str],
        sanitizers: set[str],
    ) -> tuple[list[str] | None, bool, int]:
        """
        start_id에서 sink_name을 직접 호출하는 함수까지 BFS.
        반환: (경로 or None, sanitizer가 경로상에 있는가, 최대 깊이)
        """
        # 경로 추적: queue = (current_id, path_so_far, sanitizer_seen)
        queue: list[tuple[str, list[str], bool]] = [(start_id, [start_id], False)]
        visited: set[str] = set()

        while queue:
            node_id, path, san_seen = queue.pop(0)
            if node_id in visited:
                continue
            if len(path) > _MAX_DEPTH:
                continue
            visited.add(node_id)

            callees = call_graph.get(node_id, [])
            node_name = node_id.split("::")[-1]
            san_seen_now = san_seen or (node_name in sanitizers)

            # sink에 직접 도달하는지 확인
            if sink_name in callees:
                final_path = path + [sink_id]
                return final_path, san_seen_now or (sink_name in sanitizers), len(final_path)

            # 다음 노드들을 큐에 추가
            for callee_name in callees:
                callee_id = name_to_id.get(callee_name)
                if callee_id and callee_id not in visited:
                    queue.append((callee_id, path + [callee_id], san_seen_now))

        return None, False, 0

    # ------------------------------------------------------------------
    # Candidate generation
    # ------------------------------------------------------------------

    def _generate_candidates(
        self,
        paths: list[dict],
        primitives_idx: dict[str, dict],
    ) -> list[dict]:
        candidates: list[dict] = []

        for path in paths:
            source_id = path["source"]["id"]
            prim = primitives_idx.get(source_id, {})
            result_use_links = prim.get("result_use_links", [])
            enforcement_links = prim.get("enforcement_links", [])

            # 상태 결정
            state = _determine_state(
                path_found=path["path_found"],
                sanitizer_on_path=path["sanitizer_on_path"],
                result_use_links=result_use_links,
                enforcement_links=enforcement_links,
            )

            # confidence 보정: enforcement link가 있으면 low → moderate
            confidence = "low"
            if state == "ACTIVE" and enforcement_links:
                confidence = "moderate"

            candidates.append({
                "candidate_id": f"code_{path['seed_id']}",
                "rule_id": path["rule_id"],
                "type": "structural_concern",
                "state": state,
                "source": path["source"],
                "sink": path["sink"],
                "evidence": {
                    "path_found": path["path_found"],
                    "path": path["path"],
                    "path_depth": path["path_depth"],
                    "sanitizer_on_path": path["sanitizer_on_path"],
                    "depth_limit": path["depth_limit"],
                    "boundary": path["boundary"],
                    "result_use_link_count": len(result_use_links),
                    "enforcement_link_count": len(enforcement_links),
                },
                "confidence": confidence,
                "claim": "structurally identified candidate",
                "heuristic": True,
            })

        # deterministic ordering
        return sorted(candidates, key=lambda c: c["candidate_id"])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load(self, name: str) -> dict | list:
        path = self.output_dir / name
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _determine_state(
    path_found: bool,
    sanitizer_on_path: bool,
    result_use_links: list[dict],
    enforcement_links: list[dict],
) -> str:
    if not path_found:
        return "BOUNDARY_LIMITED"
    if sanitizer_on_path:
        return "SANITIZER_AFFECTED"
    # enforcement link가 있으면 guard가 action을 gate할 가능성 → 낮은 위험
    if enforcement_links:
        return "SANITIZER_AFFECTED"
    return "ACTIVE"
