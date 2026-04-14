"""소스 트리 인덱서 — shared 아티팩트(symbols, files, call_graph, function_summaries, primitives) 생성."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from check_me.core.primitives import PrimitivesExtractor, primitives_to_dict


@dataclass
class IndexResult:
    file_count: int
    function_count: int


# 함수 본문 추출 패턴: 여는 중괄호부터 대응 닫는 중괄호까지
_FUNC_DECL_RE = re.compile(
    r"^(?!#)[\w\s\*]+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)


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
        self._extractor = PrimitivesExtractor()

    def run(self) -> IndexResult:
        files = self._collect_files()
        functions, bodies = self._extract_functions_with_bodies(files)
        call_graph = self._build_call_graph(functions, bodies)
        summaries = self._make_summaries(functions, bodies)
        primitives = self._extract_primitives(functions, bodies)

        self._write_artifact("files.json", files)
        self._write_artifact("symbols.json", {"functions": functions})
        self._write_artifact("call_graph.json", call_graph)
        self._write_artifact("function_summaries.json", summaries)
        self._write_artifact("primitives.json", primitives)
        self._write_artifact(
            "stats.json",
            {
                "file_count": len(files),
                "function_count": len(functions),
                "call_edge_count": sum(len(v) for v in call_graph.values()),
                "primitives_count": len(primitives),
                "parser_backend": self._parser_backend(),
                "compile_commands_used": self.compile_commands is not None,
            },
        )

        return IndexResult(file_count=len(files), function_count=len(functions))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parser_backend(self) -> str:
        return "heuristic"

    def _collect_files(self) -> list[dict]:
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
        paths = sorted(
            p for p in self.dir_path.rglob("*") if p.suffix in extensions
        )
        return [
            {"path": str(p.relative_to(self.dir_path)), "size": p.stat().st_size}
            for p in paths
        ]

    def _extract_functions_with_bodies(
        self, files: list[dict]
    ) -> tuple[list[dict], dict[str, str]]:
        """함수 메타데이터와 본문을 함께 추출한다."""
        functions: list[dict] = []
        bodies: dict[str, str] = {}  # function_id -> body text
        seen: set[str] = set()

        for file_info in files:
            path = self.dir_path / file_info["path"]
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for m in _FUNC_DECL_RE.finditer(text):
                name = m.group("name")
                # 예약어/매크로 필터
                if name in {"if", "for", "while", "switch", "do", "else",
                            "return", "struct", "union", "enum", "typedef"}:
                    continue

                key = f"{file_info['path']}::{name}"
                if key in seen:
                    continue
                seen.add(key)

                line = text[: m.start()].count("\n") + 1
                body = self._extract_body(text, m.end() - 1)  # m.end()-1 은 '{'

                functions.append(
                    {
                        "id": key,
                        "name": name,
                        "file": file_info["path"],
                        "line": line,
                        "parser_backend": "heuristic",
                    }
                )
                bodies[key] = body

        functions.sort(key=lambda f: (f["file"], f["line"]))
        return functions, bodies

    def _extract_body(self, text: str, brace_start: int) -> str:
        """중괄호 매칭으로 함수 본문을 추출한다."""
        depth = 0
        i = brace_start
        while i < len(text):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_start : i + 1]
            i += 1
        return text[brace_start:]  # fallback: 끝까지

    def _build_call_graph(
        self, functions: list[dict], bodies: dict[str, str]
    ) -> dict[str, list[str]]:
        """함수 본문 안에서 직접 호출되는 함수 이름을 추출한다."""
        func_names = {f["name"] for f in functions}
        call_graph: dict[str, list[str]] = {}

        for func in functions:
            fid = func["id"]
            body = bodies.get(fid, "")
            callees: set[str] = set()

            for callee in func_names:
                if callee == func["name"]:
                    continue
                # 함수 본문 안에서 `callee(` 패턴 탐색
                if re.search(r"\b" + re.escape(callee) + r"\s*\(", body):
                    callees.add(callee)

            call_graph[fid] = sorted(callees)

        return call_graph

    def _make_summaries(
        self, functions: list[dict], bodies: dict[str, str]
    ) -> list[dict]:
        return [
            {
                "id": f["id"],
                "name": f["name"],
                "file": f["file"],
                "line": f["line"],
                "body_lines": bodies.get(f["id"], "").count("\n") + 1,
                "summary": None,
                "confidence": "low",
            }
            for f in functions
        ]

    def _extract_primitives(
        self, functions: list[dict], bodies: dict[str, str]
    ) -> list[dict]:
        result: list[dict] = []
        for func in functions:
            fid = func["id"]
            body = bodies.get(fid, "")
            prims = self._extractor.extract(fid, body)
            result.append(primitives_to_dict(prims))
        return result

    def _write_artifact(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
