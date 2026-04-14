"""아티팩트 유효성 검사."""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED_SHARED_ARTIFACTS = [
    "files.json",
    "symbols.json",
    "call_graph.json",
    "function_summaries.json",
    "primitives.json",
    "stats.json",
]

FORBIDDEN_CLAIM_WORDS = [
    "proven vulnerability",
    "exploitable",
    "execution-path verified",
    "race detected",
    "timing attack detected",
    "cryptographic weakness proven",
]


class Validator:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def run(self) -> tuple[bool, list[str]]:
        issues: list[str] = []

        # 1. 필수 아티팩트 존재 확인
        for name in REQUIRED_SHARED_ARTIFACTS:
            path = self.output_dir / name
            if not path.exists():
                issues.append(f"missing artifact: {name}")
                continue
            # 2. JSON 파싱 가능 여부
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                issues.append(f"invalid JSON in {name}: {e}")

        # 3. candidates 파일에 금지 표현 포함 여부
        for candidate_file in self.output_dir.glob("*candidates*.json"):
            text = candidate_file.read_text(encoding="utf-8").lower()
            for word in FORBIDDEN_CLAIM_WORDS:
                if word.lower() in text:
                    issues.append(f"forbidden claim '{word}' found in {candidate_file.name}")

        return len(issues) == 0, issues
