"""소스 트리 인덱서 — shared 아티팩트(symbols, files, call_graph, function_summaries) 생성."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IndexResult:
    file_count: int
    function_count: int


class Indexer:
    def __init__(
        self,
        dir_path: Path,
        compile_commands: Path | None,
        output_dir: Path,
    ) -> None:
        self.dir_path = dir_path
        self.compile_commands = compile_commands
        self.output_dir = output_dir

    def run(self) -> IndexResult:
        files = self._collect_files()
        functions = self._extract_functions(files)
        call_graph = self._build_call_graph(functions)

        self._write_artifact("files.json", files)
        self._write_artifact("symbols.json", {"functions": functions})
        self._write_artifact("call_graph.json", call_graph)
        self._write_artifact(
            "function_summaries.json",
            self._make_summaries(functions),
        )
        self._write_artifact(
            "stats.json",
            {
                "file_count": len(files),
                "function_count": len(functions),
                "call_edge_count": sum(len(v) for v in call_graph.values()),
                "parser_backend": self._parser_backend(),
                "compile_commands_used": self.compile_commands is not None,
            },
        )

        return IndexResult(file_count=len(files), function_count=len(functions))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parser_backend(self) -> str:
        """현재는 heuristic(regex) 파서만 지원. clang_json 백엔드는 추후."""
        return "heuristic"

    def _collect_files(self) -> list[dict]:
        """C/C++ 소스 파일 목록을 결정론적 순서로 수집한다."""
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
        paths = sorted(
            p for p in self.dir_path.rglob("*") if p.suffix in extensions
        )
        return [
            {"path": str(p.relative_to(self.dir_path)), "size": p.stat().st_size}
            for p in paths
        ]

    def _extract_functions(self, files: list[dict]) -> list[dict]:
        """파일에서 함수 시그니처를 추출한다 (heuristic 파서)."""
        import re

        pattern = re.compile(
            r"^[\w\s\*]+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )
        functions: list[dict] = []
        seen: set[str] = set()

        for file_info in files:
            path = self.dir_path / file_info["path"]
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for m in pattern.finditer(text):
                name = m.group("name")
                key = f"{file_info['path']}::{name}"
                if key in seen:
                    continue
                seen.add(key)
                line = text[: m.start()].count("\n") + 1
                functions.append(
                    {
                        "id": key,
                        "name": name,
                        "file": file_info["path"],
                        "line": line,
                        "parser_backend": "heuristic",
                    }
                )

        return sorted(functions, key=lambda f: (f["file"], f["line"]))

    def _build_call_graph(self, functions: list[dict]) -> dict[str, list[str]]:
        """direct call graph를 구성한다 (heuristic)."""
        func_names = {f["name"] for f in functions}
        call_graph: dict[str, list[str]] = {}

        for func in functions:
            path = self.dir_path / func["file"]
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                call_graph[func["id"]] = []
                continue

            callees: list[str] = []
            for callee in func_names:
                if callee == func["name"]:
                    continue
                if f"{callee}(" in text:
                    callees.append(callee)

            call_graph[func["id"]] = sorted(set(callees))

        return call_graph

    def _make_summaries(self, functions: list[dict]) -> list[dict]:
        return [
            {
                "id": f["id"],
                "name": f["name"],
                "file": f["file"],
                "line": f["line"],
                "summary": None,
                "confidence": "low",
            }
            for f in functions
        ]

    def _write_artifact(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
