"""Code Mode — 코드 중심 보안 후보 생성."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from check_me.config import LLMConfig


@dataclass
class ModeResult:
    candidate_count: int


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
        symbols = self._load_artifact("symbols.json")
        call_graph = self._load_artifact("call_graph.json")
        security_model = self._load_artifact("security_model.json")

        matches = self._match_source_sink(symbols, security_model)
        seeds = self._build_flow_seeds(matches)
        paths = self._bounded_propagation(seeds, call_graph)
        candidates = self._generate_candidates(paths)

        self._write_artifact("source_sink_matches.json", matches)
        self._write_artifact("flow_seeds.json", seeds)
        self._write_artifact("propagation_paths.json", paths)
        self._write_artifact("code_candidates.json", candidates)

        return ModeResult(candidate_count=len(candidates))

    # ------------------------------------------------------------------

    def _load_artifact(self, name: str) -> dict | list:
        path = self.output_dir / name
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _match_source_sink(self, symbols: dict, security_model: dict) -> list[dict]:
        """source/sink/sanitizer 매칭 (heuristic)."""
        rules = security_model.get("rules", []) if isinstance(security_model, dict) else []
        functions = symbols.get("functions", []) if isinstance(symbols, dict) else []

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
                    matches.append(
                        {
                            "rule_id": rule.get("id", "unknown"),
                            "source": src,
                            "sink": sink,
                            "sanitizers_found": found_sanitizers,
                            "confidence": "low",
                        }
                    )

        return sorted(matches, key=lambda m: (m["rule_id"], m["source"]["id"], m["sink"]["id"]))

    def _build_flow_seeds(self, matches: list[dict]) -> list[dict]:
        return [
            {
                "seed_id": f"seed_{i}",
                "rule_id": m["rule_id"],
                "source_id": m["source"]["id"],
                "sink_id": m["sink"]["id"],
                "sanitizer_count": len(m["sanitizers_found"]),
            }
            for i, m in enumerate(matches)
        ]

    def _bounded_propagation(self, seeds: list[dict], call_graph: dict) -> list[dict]:
        """depth-bounded call graph traversal."""
        MAX_DEPTH = 5
        paths: list[dict] = []

        for seed in seeds:
            source_id = seed["source_id"]
            reachable = self._bfs(source_id, call_graph, MAX_DEPTH)
            paths.append(
                {
                    "seed_id": seed["seed_id"],
                    "source_id": source_id,
                    "reachable_count": len(reachable),
                    "depth_limit": MAX_DEPTH,
                    "boundary": "direct_calls_only",
                }
            )

        return paths

    def _bfs(self, start: str, call_graph: dict, max_depth: int) -> set[str]:
        visited: set[str] = set()
        queue = [(start, 0)]
        while queue:
            node, depth = queue.pop(0)
            if node in visited or depth >= max_depth:
                continue
            visited.add(node)
            for callee in call_graph.get(node, []):
                queue.append((callee, depth + 1))
        return visited

    def _generate_candidates(self, paths: list[dict]) -> list[dict]:
        candidates: list[dict] = []
        for path in paths:
            if path["reachable_count"] == 0:
                state = "BOUNDARY_LIMITED"
            else:
                state = "ACTIVE"

            candidates.append(
                {
                    "candidate_id": f"code_{path['seed_id']}",
                    "type": "structural_concern",
                    "state": state,
                    "evidence": {
                        "source_id": path["source_id"],
                        "reachable_count": path["reachable_count"],
                        "depth_limit": path["depth_limit"],
                        "boundary": path["boundary"],
                    },
                    "confidence": "low",
                    "claim": "structurally identified candidate",
                }
            )

        return candidates

    def _write_artifact(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
