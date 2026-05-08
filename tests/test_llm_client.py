"""Pytest for check_me.llm.client — wraps the OpenAI SDK.

These tests mock the SDK's ``chat.completions.create`` and
``responses.create`` methods so we exercise the wrapper's request
shape and response flattening for both wire formats without
touching the network.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from check_me.llm.client import ChatRequest, ChatResponse, chat, make_client
from check_me.llm.config import Config


def _cfg(**overrides) -> Config:
    base = dict(
        url="https://x.test/v1",
        key="k-test-1234",
        model="m1",
        temperature=0.1,
        max_tokens=4096,
    )
    base.update(overrides)
    return Config(**base)


class _Capturing:
    """Mimics ``client.chat.completions.create``.

    Captures the kwargs it was called with and returns a canned
    OpenAI-shaped response object whose ``model_dump()`` is
    deterministic. Tests assert on captured.kwargs.
    """

    def __init__(self, response: dict) -> None:
        self.response = response
        self.kwargs: dict | None = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        # SimpleNamespace with a model_dump method like the real SDK.
        ns = SimpleNamespace()
        ns.model_dump = lambda: self.response
        return ns


def _client_with(create_obj):
    """Wrap a stand-in into the SDK shape ``client.chat.completions
    .create`` and also expose ``client.responses.create`` so tests
    can target either wire format with the same fixture builder."""
    return SimpleNamespace(
        chat=SimpleNamespace(completions=create_obj),
        responses=create_obj,
    )


def _ok_response(content="hi", finish="stop", usage=None):
    return {
        "choices": [
            {
                "index": 0,
                "finish_reason": finish,
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": usage or {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        "model": "m1",
        "id": "test-id",
    }


# --------------------------------------------------------------------------- #
# make_client
# --------------------------------------------------------------------------- #


def test_make_client_uses_url_and_key():
    cfg = _cfg(url="https://x.test/v1", key="abc")
    c = make_client(cfg)
    assert c.base_url == "https://x.test/v1/" or str(c.base_url) == "https://x.test/v1/"
    # The key is not exposed as a plain attribute on every SDK version.
    # We just verify the client constructed without error.
    assert c is not None


# --------------------------------------------------------------------------- #
# chat
# --------------------------------------------------------------------------- #


def test_chat_passes_model_messages_temperature_max_tokens():
    cap = _Capturing(_ok_response("hello"))
    client = _client_with(cap)
    cfg = _cfg(model="my-model", temperature=0.3, max_tokens=2048)
    req = ChatRequest(messages=[{"role": "user", "content": "hi"}])

    resp = chat(client, cfg, req)

    assert cap.kwargs is not None
    assert cap.kwargs["model"] == "my-model"
    assert cap.kwargs["messages"] == [{"role": "user", "content": "hi"}]
    assert cap.kwargs["temperature"] == 0.3
    assert cap.kwargs["max_tokens"] == 2048
    # response_format must NOT be set unless json_object=True.
    assert "response_format" not in cap.kwargs

    assert resp.content == "hello"
    assert resp.finish_reason == "stop"


def test_chat_response_format_set_when_json_object_true():
    cap = _Capturing(_ok_response('{"ok":true}'))
    req = ChatRequest(
        messages=[{"role": "user", "content": "give json"}],
        json_object=True,
    )
    chat(_client_with(cap), _cfg(), req)
    assert cap.kwargs["response_format"] == {"type": "json_object"}


def test_chat_extra_kwargs_passed_through():
    cap = _Capturing(_ok_response("ok"))
    req = ChatRequest(
        messages=[{"role": "user", "content": "x"}],
        extra={"reasoning_effort": "none", "stop": ["END"]},
    )
    chat(_client_with(cap), _cfg(), req)
    assert cap.kwargs["reasoning_effort"] == "none"
    assert cap.kwargs["stop"] == ["END"]


def test_chat_extra_overrides_max_tokens():
    """json_call.py bumps max_tokens via ``extra`` on length-finish
    retries. The override must reach the SDK call."""
    cap = _Capturing(_ok_response("ok"))
    req = ChatRequest(
        messages=[{"role": "user", "content": "x"}],
        extra={"max_tokens": 8192},
    )
    chat(_client_with(cap), _cfg(max_tokens=4096), req)
    assert cap.kwargs["max_tokens"] == 8192


def test_chat_response_flattens_token_usage():
    cap = _Capturing(
        _ok_response(
            "x",
            usage={"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        )
    )
    resp = chat(_client_with(cap), _cfg(), ChatRequest(messages=[]))
    assert resp.prompt_tokens == 11
    assert resp.completion_tokens == 7
    assert resp.total_tokens == 18


def test_chat_response_handles_missing_content():
    """Gemini 2.5 returns ``message`` without ``content`` when
    finish_reason=length (thinking ate the budget). Wrapper must not
    KeyError."""
    cap = _Capturing(
        {
            "choices": [
                {"index": 0, "finish_reason": "length", "message": {"role": "assistant"}}
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 0, "total_tokens": 50},
            "model": "m1",
        }
    )
    resp = chat(_client_with(cap), _cfg(), ChatRequest(messages=[]))
    assert resp.content == ""
    assert resp.finish_reason == "length"


def test_chat_response_handles_missing_usage():
    """Some providers omit usage on errors. Wrapper must default to 0."""
    cap = _Capturing(
        {
            "choices": [
                {"index": 0, "finish_reason": "stop", "message": {"content": "ok"}}
            ],
            "model": "m1",
        }
    )
    resp = chat(_client_with(cap), _cfg(), ChatRequest(messages=[]))
    assert resp.prompt_tokens == 0
    assert resp.total_tokens == 0


def test_chat_response_raw_dict_preserved():
    cap = _Capturing(_ok_response("payload"))
    resp = chat(_client_with(cap), _cfg(), ChatRequest(messages=[]))
    assert resp.raw["id"] == "test-id"
    assert resp.raw["model"] == "m1"


# --------------------------------------------------------------------------- #
# Responses API + GPT-5 / Codex routing
# --------------------------------------------------------------------------- #


def _responses_ok_response(text="hi", status="completed", usage=None):
    """Canonical Responses-API completion shape.

    Mirrors the live SDK's ``output[].content[]`` structure with one
    ``output_text`` chunk; ``usage`` uses the Responses-API field
    names (``input_tokens`` / ``output_tokens``)."""
    return {
        "id": "resp-test-id",
        "model": "codex-test",
        "status": status,
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
        "usage": usage
        or {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
    }


def test_codex_model_auto_routes_to_responses_api():
    """``api_mode=auto`` picks Responses for Codex-family models —
    the call lands on ``client.responses.create`` and uses Responses
    field names (``input``, ``max_output_tokens``)."""
    cap = _Capturing(_responses_ok_response("ok"))
    cfg = _cfg(model="codex-mini", max_tokens=2048)
    chat(_client_with(cap), cfg, ChatRequest(messages=[{"role": "user", "content": "x"}]))
    assert cap.kwargs is not None
    assert cap.kwargs["model"] == "codex-mini"
    # Responses uses ``input`` / ``max_output_tokens``.
    assert cap.kwargs["input"] == [{"role": "user", "content": "x"}]
    assert cap.kwargs["max_output_tokens"] == 2048
    # Reasoning-family models drop the temperature field.
    assert "temperature" not in cap.kwargs
    # Chat-Completions field names are NOT present.
    assert "messages" not in cap.kwargs
    assert "max_tokens" not in cap.kwargs


def test_responses_api_json_format_uses_text_format_field():
    """Responses replaces ``response_format`` with ``text``: when
    ``json_object=True`` the wrapper emits ``text={"format": ...}``
    so the Responses endpoint accepts the JSON-mode signal."""
    cap = _Capturing(_responses_ok_response('{"ok":true}'))
    cfg = _cfg(model="codex-mini")
    chat(
        _client_with(cap),
        cfg,
        ChatRequest(messages=[], json_object=True),
    )
    assert cap.kwargs["text"] == {"format": {"type": "json_object"}}
    assert "response_format" not in cap.kwargs


def test_responses_api_extra_max_tokens_is_remapped():
    """``json_call`` bumps ``max_tokens`` via ``extra`` on length
    retries. For a Responses call the wrapper translates that into
    ``max_output_tokens`` so the SDK accepts the bump."""
    cap = _Capturing(_responses_ok_response("ok"))
    cfg = _cfg(model="codex-mini", max_tokens=2048)
    req = ChatRequest(messages=[], extra={"max_tokens": 8192})
    chat(_client_with(cap), cfg, req)
    assert cap.kwargs["max_output_tokens"] == 8192
    assert "max_tokens" not in cap.kwargs


def test_responses_api_incomplete_reason_surfaces_as_finish_reason():
    """Responses' truncation signal is
    ``incomplete_details.reason``; the wrapper exposes it through
    ``ChatResponse.finish_reason`` so ``json_call`` length retries
    keep working unchanged."""
    cap = _Capturing(
        {
            "id": "resp-x",
            "model": "codex-mini",
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": ""}],
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 0,
                "total_tokens": 10,
            },
        }
    )
    resp = chat(
        _client_with(cap),
        _cfg(model="codex-mini"),
        ChatRequest(messages=[]),
    )
    assert resp.finish_reason == "max_output_tokens"
    # Usage maps onto Chat-Completions field names.
    assert resp.prompt_tokens == 10
    assert resp.completion_tokens == 0


def test_api_mode_chat_completions_overrides_codex_auto_route():
    """Forcing ``api_mode="chat_completions"`` keeps Codex models on
    the Chat Completions endpoint — operator escape hatch when the
    auto-detect mis-routes."""
    cap = _Capturing(_ok_response("ok"))
    cfg = _cfg(model="codex-mini", api_mode="chat_completions")
    chat(_client_with(cap), cfg, ChatRequest(messages=[]))
    # Chat-Completions field names present, Responses ones absent.
    assert "messages" in cap.kwargs
    assert "input" not in cap.kwargs
    assert "max_output_tokens" not in cap.kwargs


def test_gpt5_chat_completions_uses_max_completion_tokens_and_drops_temperature():
    """OpenAI's reasoning-tier Chat-Completions endpoint expects
    ``max_completion_tokens`` and rejects an explicit
    ``temperature``. The wrapper applies both rules client-side."""
    cap = _Capturing(_ok_response("ok"))
    cfg = _cfg(model="gpt-5-mini", temperature=0.3, max_tokens=2048)
    chat(_client_with(cap), cfg, ChatRequest(messages=[]))
    assert cap.kwargs["max_completion_tokens"] == 2048
    assert "max_tokens" not in cap.kwargs
    assert "temperature" not in cap.kwargs


def test_gpt5_extra_max_tokens_remaps_to_max_completion_tokens():
    """``json_call``'s ``extra={"max_tokens": ...}`` bump must reach
    the GPT-5 endpoint as ``max_completion_tokens``."""
    cap = _Capturing(_ok_response("ok"))
    cfg = _cfg(model="gpt-5-mini", max_tokens=2048)
    req = ChatRequest(messages=[], extra={"max_tokens": 8192})
    chat(_client_with(cap), cfg, req)
    assert cap.kwargs["max_completion_tokens"] == 8192


def test_responses_api_reasoning_effort_extra_is_remapped():
    """Reasoning effort travels as ``reasoning_effort`` in Chat
    Completions; Responses expects it as ``reasoning={"effort":
    ...}``. The wrapper translates the same call-site shape so
    callers stay format-agnostic."""
    cap = _Capturing(_responses_ok_response("ok"))
    cfg = _cfg(model="codex-mini")
    req = ChatRequest(
        messages=[],
        extra={"reasoning_effort": "medium"},
    )
    chat(_client_with(cap), cfg, req)
    assert cap.kwargs["reasoning"] == {"effort": "medium"}
    # Chat-Completions vocabulary should not leak into the kwargs.
    assert "reasoning_effort" not in cap.kwargs
