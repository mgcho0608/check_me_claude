"""보안 모델 빌더 — 규칙 레지스트리를 로드하고 source/sink/sanitizer 매핑을 생성한다."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class SecurityModelResult:
    rule_count: int


class SecurityModelBuilder:
    def __init__(
        self,
        dir_path: Path,
        compile_commands: Path | None,
        registry_path: Path,
        output_dir: Path,
    ) -> None:
        self.dir_path = dir_path
        self.compile_commands = compile_commands
        self.registry_path = registry_path
        self.output_dir = output_dir

    def run(self) -> SecurityModelResult:
        registry = self._load_registry()
        self._write_artifact("security_model.json", registry)
        return SecurityModelResult(rule_count=len(registry.get("rules", [])))

    def _load_registry(self) -> dict:
        with self.registry_path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _write_artifact(self, name: str, data: object) -> None:
        path = self.output_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
