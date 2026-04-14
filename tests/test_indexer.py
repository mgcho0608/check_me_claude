"""Indexer 테스트 — shared 아티팩트 생성 및 결정론성."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_me.core.indexer import Indexer


def test_indexer_creates_all_artifacts(tmp_path, update_fixture_dir):
    indexer = Indexer(
        dir_path=update_fixture_dir,
        compile_commands=None,
        output_dir=tmp_path,
    )
    result = indexer.run()

    assert result.file_count > 0
    assert result.function_count > 0

    for artifact in ["files.json", "symbols.json", "call_graph.json",
                     "function_summaries.json", "stats.json"]:
        assert (tmp_path / artifact).exists(), f"missing: {artifact}"


def test_indexer_json_valid(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()

    for name in ["files.json", "symbols.json", "call_graph.json",
                 "function_summaries.json", "stats.json"]:
        data = json.loads((tmp_path / name).read_text(encoding="utf-8"))
        assert data is not None


def test_indexer_deterministic(tmp_path, update_fixture_dir):
    """동일 입력에 대해 동일한 결과가 나와야 한다."""
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    out1.mkdir()
    out2.mkdir()

    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=out1).run()
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=out2).run()

    for name in ["files.json", "symbols.json", "call_graph.json"]:
        assert (out1 / name).read_text(encoding="utf-8") == (out2 / name).read_text(encoding="utf-8"), \
            f"{name} is not deterministic"


def test_indexer_detects_functions(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    symbols = json.loads((tmp_path / "symbols.json").read_text(encoding="utf-8"))
    func_names = [f["name"] for f in symbols["functions"]]

    for expected in ["install_firmware", "verify_signature", "apply_update"]:
        assert expected in func_names, f"expected function not found: {expected}"


def test_stats_fields(tmp_path, update_fixture_dir):
    Indexer(dir_path=update_fixture_dir, compile_commands=None, output_dir=tmp_path).run()
    stats = json.loads((tmp_path / "stats.json").read_text(encoding="utf-8"))

    assert "file_count" in stats
    assert "function_count" in stats
    assert "parser_backend" in stats
    assert stats["file_count"] > 0
