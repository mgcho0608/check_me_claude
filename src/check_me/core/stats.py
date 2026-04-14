"""stats 아티팩트 읽기 및 요약."""

from __future__ import annotations

import json
from pathlib import Path


class StatsReader:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def summarize(self) -> str:
        stats_path = self.output_dir / "stats.json"
        if not stats_path.exists():
            return "stats.json not found — run `check_me index` first"

        data = json.loads(stats_path.read_text(encoding="utf-8"))
        parts = []
        for k, v in data.items():
            parts.append(f"{k}={v}")
        return ", ".join(parts)
