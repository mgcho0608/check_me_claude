"""Tests for the chunked, parallel miner architecture."""

from __future__ import annotations

from typing import Any

from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config
from check_me.step2 import miner as miner_mod
from check_me.step2.substrate_slice import SubstrateSlice


def _cfg(temperature: float = 0.1) -> Config:
    return Config(
        url="https://example/v1", key="k",
        model="m", temperature=temperature, max_tokens=4096,
    )


def _resp(json_text: str, finish_reason: str = "stop") -> ChatResponse:
    return ChatResponse(
        content=json_text,
        finish_reason=finish_reason,
        prompt_tokens=10,
        completion_tokens=10,
        total_tokens=20,
        model="m",
        raw={"choices": [{"finish_reason": finish_reason, "message": {"content": json_text}}]},
    )


def _slice_with_candidates(names: list[str]) -> SubstrateSlice:
    return SubstrateSlice(
        project="p", cve="CVE-T",
        candidate_functions=list(names),
        trust_boundaries=[
            {"kind": "network_socket", "function": n,
             "file": f"{n}.c", "line": 1, "direction": "untrusted_to_trusted"}
            for n in names
        ],
    )


class _RecordingChat:
    """chat_fn that records every call's chunk identifier (extracted
    from the user prompt) and returns a canned per-chunk response."""

    def __init__(self, responses_by_first_candidate: dict[str, str]):
        self.responses_by_first_candidate = responses_by_first_candidate
        self.calls: list[dict[str, Any]] = []

    def __call__(self, client: Any, config: Config, request: ChatRequest) -> ChatResponse:
        user_msg = request.messages[-1]["content"]
        # Find the first "- name" line (chunk first candidate).
        first_cand = None
        for line in user_msg.splitlines():
            if line.startswith("- "):
                first_cand = line[2:].strip()
                break
        self.calls.append({
            "first_candidate": first_cand,
            "user_msg_len": len(user_msg),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        })
        if first_cand is None:
            raise AssertionError("chunked miner sent no '- ' candidate list")
        if first_cand not in self.responses_by_first_candidate:
            raise AssertionError(f"unexpected chunk first_candidate={first_cand!r}")
        return _resp(self.responses_by_first_candidate[first_cand])


def _miner_resp(candidates: list[dict[str, Any]]) -> str:
    """Build a miner-output JSON string."""
    import json as _json
    return _json.dumps({"candidates": candidates})


def _row(fn: str, file: str | None = None, **kw) -> dict[str, Any]:
    base = {
        "id": "EP-tmp",
        "function": fn,
        "file": file or f"{fn}.c",
        "line": 1,
        "trigger_type": kw.pop("trigger_type", "callback"),
        "trigger_ref": kw.pop("trigger_ref", f"trust_boundaries[function={fn}]"),
        "reachability": kw.pop("reachability", "r"),
        "attacker_controllability": kw.pop("attacker_controllability", "c"),
        "supporting_substrate_edges": kw.pop(
            "supporting_substrate_edges", [f"trust_boundaries[function={fn}]"],
        ),
        "confidence": kw.pop("confidence", "medium"),
        "uncertainty": kw.pop("uncertainty", "u"),
    }
    base.update(kw)
    return base


# --------------------------------------------------------------------------- #
# Chunking behaviour
# --------------------------------------------------------------------------- #


def test_chunked_miner_partitions_candidates_into_fixed_size_chunks():
    s = _slice_with_candidates(["a", "b", "c", "d", "e"])
    seen_chunks: list[list[str]] = []

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        # Extract the chunk's candidate list from the user message.
        user = request.messages[-1]["content"]
        chunk = [
            line[2:].strip() for line in user.splitlines()
            if line.startswith("- ")
        ]
        seen_chunks.append(chunk)
        return _resp(_miner_resp([_row(chunk[0])]))

    miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=2, max_workers=1, chat_fn=fake_chat,
    )

    # Candidates are sorted before chunking ('a','b','c','d','e').
    assert seen_chunks == [["a", "b"], ["c", "d"], ["e"]], seen_chunks


def test_chunked_miner_dedupes_by_function_and_file():
    """If two chunks both propose the same (function, file)
    (e.g. via Part B discovery on overlapping patterns), keep one."""
    s = _slice_with_candidates(["a", "b"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        first = next(line[2:].strip() for line in user.splitlines() if line.startswith("- "))
        # Both chunks "discover" the same X.
        return _resp(_miner_resp([_row(first), _row("X", file="x.c")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=fake_chat,
    )

    funcs = [c["function"] for c in result.parsed["candidates"]]
    assert funcs.count("X") == 1, funcs
    assert "a" in funcs and "b" in funcs


def test_chunked_miner_assigns_global_sequential_ids():
    s = _slice_with_candidates(["a", "b", "c"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        first = next(line[2:].strip() for line in user.splitlines() if line.startswith("- "))
        return _resp(_miner_resp([_row(first)]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=fake_chat,
    )

    ids = [c["id"] for c in result.parsed["candidates"]]
    # IDs run EP-001..EP-NNN regardless of which chunk emitted them.
    assert ids == ["EP-001", "EP-002", "EP-003"], ids


def test_chunked_miner_per_chunk_diagnostic_recorded():
    s = _slice_with_candidates(["a", "b", "c"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        first = next(line[2:].strip() for line in user.splitlines() if line.startswith("- "))
        return _resp(_miner_resp([_row(first)]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=2, max_workers=1, chat_fn=fake_chat,
    )

    assert len(result.per_chunk) == 2
    assert {d["chunk_index"] for d in result.per_chunk} == {0, 1}
    for d in result.per_chunk:
        assert d["proposed"] >= 1
        assert d["kept_after_dedupe"] >= 1


def test_chunked_miner_temperature_default_is_0_1():
    """PLAN proposer/verifier split: miner gets a small but non-zero
    temperature so cross-chunk discovery can work; verifier is
    deterministic. Tests assert the wired-in default."""
    captured: dict[str, float] = {}
    s = _slice_with_candidates(["a"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        captured["temperature"] = config.temperature
        return _resp(_miner_resp([_row("a")]))

    miner_mod.mine_chunked(
        client="dummy", config=_cfg(temperature=0.7), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=fake_chat,
    )

    assert captured["temperature"] == miner_mod.DEFAULT_MINER_TEMPERATURE


def test_chunked_miner_empty_candidates_returns_empty_list():
    s = _slice_with_candidates([])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        raise AssertionError("should not be called for empty slice")

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=30, max_workers=1, chat_fn=fake_chat,
    )

    assert result.parsed["candidates"] == []
    assert result.per_chunk == []


def test_chunked_miner_parallel_path_preserves_id_order_by_file():
    """With max_workers > 1 chunks finish in non-deterministic
    order, but the merged candidate list is sorted by (file,
    function) and ids assigned globally — output is stable."""
    s = _slice_with_candidates(["alpha", "beta", "gamma", "delta"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        first = next(line[2:].strip() for line in user.splitlines() if line.startswith("- "))
        return _resp(_miner_resp([_row(first)]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=4, chat_fn=fake_chat,
    )

    files = [c["file"] for c in result.parsed["candidates"]]
    assert files == sorted(files)
    ids = [c["id"] for c in result.parsed["candidates"]]
    assert ids == [f"EP-{i:03d}" for i in range(1, len(ids) + 1)]
