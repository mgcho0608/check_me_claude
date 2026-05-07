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
    """Chunking still happens — it bounds the substrate-projection
    size per call. The miner's task is discovery (not enumeration),
    so the LLM emits new function names, NOT the chunk's
    candidates which are in the known list."""
    s = _slice_with_candidates(["a", "b", "c", "d", "e"])
    seen_focus_lists: list[list[str]] = []

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        # Extract the substrate-projection focus block (the chunk).
        # Lines after the "Substrate-projection focus" header.
        focus = []
        in_focus = False
        for line in user.splitlines():
            if line.startswith("Substrate-projection focus"):
                in_focus = True
                continue
            if in_focus:
                if line.startswith("- "):
                    focus.append(line[2:].strip())
                elif line.strip() == "":
                    break
        seen_focus_lists.append(focus)
        # The miner discovers a NEW name, NOT the chunk's known names.
        first = focus[0] if focus else "?"
        return _resp(_miner_resp([_row(f"discover_{first}")]))

    miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=2, max_workers=1, chat_fn=fake_chat,
    )

    assert seen_focus_lists == [["a", "b"], ["c", "d"], ["e"]], seen_focus_lists


def test_chunked_miner_dedupes_by_function_and_file():
    """If two chunks both discover the same (function, file)
    via overlapping indexed-dispatch patterns, keep one."""
    s = _slice_with_candidates(["a", "b"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        # Every chunk "discovers" the same new X.
        return _resp(_miner_resp([_row("X", file="x.c")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=fake_chat,
    )

    funcs = [c["function"] for c in result.parsed["candidates"]]
    # Two chunks each emitted X — dedup by (function, file) -> 1 row.
    assert funcs.count("X") == 1, funcs


def test_chunked_miner_filters_known_candidates_from_llm_output():
    """The discovery contract: any function whose name is in
    known_candidates is dropped at merge time, even if the LLM
    emits it. The deterministic synthetic pool feeds those to
    the verifier separately; re-emission in miner output is wasted
    work."""
    s = _slice_with_candidates(["a", "b"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        # Misbehaving LLM: emits both a known function ("a") and a
        # new discovery ("zeta"). Merge must drop "a".
        return _resp(_miner_resp([_row("a"), _row("zeta")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=2, max_workers=1, chat_fn=fake_chat,
    )

    funcs = [c["function"] for c in result.parsed["candidates"]]
    assert "a" not in funcs, funcs
    assert "zeta" in funcs, funcs


def test_chunked_miner_does_NOT_assign_global_ids():
    """ID assignment is deferred to the runner so it can merge
    synthetic + discovered before numbering globally. The miner
    output keeps whatever id the LLM emitted (or the runner-side
    later assigns)."""
    s = _slice_with_candidates(["a", "b", "c"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        return _resp(_miner_resp([_row("discover_zeta", file="z.c")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=fake_chat,
    )

    # Result candidates exist but ids are NOT runner-style.
    # _row sets id="EP-tmp", which the runner overrides.
    cands = result.parsed["candidates"]
    assert len(cands) >= 1
    assert all(c.get("id") == "EP-tmp" for c in cands)


def test_chunked_miner_per_chunk_diagnostic_recorded():
    s = _slice_with_candidates(["a", "b", "c"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        # Each chunk emits one new discovery whose name encodes
        # the chunk's substrate-projection focus list (so each
        # chunk's discovery is unique and not deduped at merge).
        user = request.messages[-1]["content"]
        focus_first = None
        in_focus = False
        for line in user.splitlines():
            if line.startswith("Substrate-projection focus"):
                in_focus = True
                continue
            if in_focus and line.startswith("- "):
                focus_first = line[2:].strip()
                break
        return _resp(_miner_resp([_row(f"new_{focus_first}",
                                       file=f"new_{focus_first}.c")]))

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


def test_chunked_miner_failed_chunk_does_not_abort_run():
    """A single chunk's exception (e.g. exhausted 429 retry budget)
    must NOT propagate through ``mine_chunked`` and abort the run.
    Surviving chunks contribute their discoveries; the failed
    chunk is recorded in ``per_chunk`` with ``ok=False`` so the
    operator can re-run."""
    s = _slice_with_candidates(["a", "b", "c", "d"])

    def flaky_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        # Find the first focus-block "- name" line.
        focus_first = None
        in_focus = False
        for line in user.splitlines():
            if line.startswith("Substrate-projection focus"):
                in_focus = True
                continue
            if in_focus and line.startswith("- "):
                focus_first = line[2:].strip()
                break
        # Fail on chunk starting with "c"; succeed on others.
        if focus_first == "c":
            raise RuntimeError("simulated 429 retry budget exhausted")
        return _resp(_miner_resp([_row(f"new_{focus_first}",
                                       file=f"new_{focus_first}.c")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=1, chat_fn=flaky_chat,
    )

    funcs = sorted(c["function"] for c in result.parsed["candidates"])
    # 'c' chunk fails — discoveries from a, b, d chunks survive.
    assert funcs == ["new_a", "new_b", "new_d"], funcs
    failed = [d for d in result.per_chunk if not d.get("ok", True)]
    assert len(failed) == 1
    assert "simulated" in failed[0]["error"]


def test_chunked_miner_parallel_path_preserves_file_order():
    """With max_workers > 1 chunks finish in non-deterministic
    order, but the merged candidate list is sorted by (file,
    function) for stable serialisation."""
    s = _slice_with_candidates(["alpha", "beta", "gamma", "delta"])

    def fake_chat(client, config, request: ChatRequest) -> ChatResponse:
        user = request.messages[-1]["content"]
        focus_first = None
        in_focus = False
        for line in user.splitlines():
            if line.startswith("Substrate-projection focus"):
                in_focus = True
                continue
            if in_focus and line.startswith("- "):
                focus_first = line[2:].strip()
                break
        # Discover one new candidate per chunk.
        return _resp(_miner_resp([_row(f"new_{focus_first}",
                                       file=f"new_{focus_first}.c")]))

    result = miner_mod.mine_chunked(
        client="dummy", config=_cfg(), slice_=s,
        chunk_size=1, max_workers=4, chat_fn=fake_chat,
    )

    files = [c["file"] for c in result.parsed["candidates"]]
    assert files == sorted(files)
