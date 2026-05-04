"""Pytest for check_me.llm.json_call — retry on length / parse / schema.

Uses an injectable ``chat_fn`` to drive the call sequence without any
real network or SDK involvement. Each test specifies the canned
responses the stub should return in order.
"""

from __future__ import annotations

from typing import Any

import pytest

from check_me.llm.client import ChatRequest, ChatResponse
from check_me.llm.config import Config
from check_me.llm.json_call import (
    JsonCallError,
    SchemaValidationError,
    chat_json,
)


def _cfg(**ovr) -> Config:
    base = dict(
        url="https://x.test/v1",
        key="k", model="m", temperature=0.1, max_tokens=2048,
    )
    base.update(ovr)
    return Config(**base)


def _resp(content: str, finish: str = "stop", tokens: int = 10) -> ChatResponse:
    return ChatResponse(
        content=content,
        finish_reason=finish,
        prompt_tokens=5,
        completion_tokens=5,
        total_tokens=tokens,
        model="m",
        raw={"choices": [{"finish_reason": finish, "message": {"content": content}}]},
    )


class _SequencedChat:
    """A chat_fn substitute that returns canned responses in order and
    records the kwargs each call received."""

    def __init__(self, responses: list[ChatResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, client, config, request: ChatRequest) -> ChatResponse:
        if not self.responses:
            raise AssertionError("no more canned responses")
        self.calls.append(
            {
                "max_tokens": request.extra.get("max_tokens", config.max_tokens),
                "messages": list(request.messages),
                "json_object": request.json_object,
            }
        )
        return self.responses.pop(0)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_chat_json_returns_parsed_object_on_first_try():
    seq = _SequencedChat([_resp('{"a": 1}')])
    result = chat_json(
        client=None, config=_cfg(),
        system="sys", user="usr",
        chat_fn=seq,
    )
    assert result.parsed == {"a": 1}
    assert len(seq.calls) == 1
    assert seq.calls[0]["json_object"] is True
    assert result.attempts[0]["outcome"] == "ok"


def test_chat_json_passes_system_and_user_messages():
    seq = _SequencedChat([_resp('{"ok": true}')])
    chat_json(
        client=None, config=_cfg(),
        system="you are a helpful assistant",
        user="please reply with json",
        chat_fn=seq,
    )
    msgs = seq.calls[0]["messages"]
    assert msgs[0] == {"role": "system", "content": "you are a helpful assistant"}
    assert msgs[1] == {"role": "user", "content": "please reply with json"}


# --------------------------------------------------------------------------- #
# Length-truncation retry
# --------------------------------------------------------------------------- #


def test_length_finish_triggers_max_tokens_doubling_then_succeeds():
    seq = _SequencedChat(
        [
            _resp("", finish="length"),     # truncated: thinking ate budget
            _resp('{"got": "it"}'),          # second attempt with bigger budget
        ]
    )
    result = chat_json(
        client=None, config=_cfg(max_tokens=2048),
        system="s", user="u",
        chat_fn=seq, max_retries=2,
    )
    assert result.parsed == {"got": "it"}
    # First attempt at 2048, second at 4096 (doubled).
    assert seq.calls[0]["max_tokens"] == 2048
    assert seq.calls[1]["max_tokens"] == 4096


def test_length_retry_caps_at_ceiling():
    seq = _SequencedChat([_resp("", "length")] * 5)
    with pytest.raises(JsonCallError, match="ceiling"):
        chat_json(
            client=None, config=_cfg(max_tokens=4096),
            system="s", user="u",
            chat_fn=seq, max_retries=4, max_tokens_ceiling=8192,
        )


def test_length_retry_does_not_append_followups():
    """A length-truncation retry uses the ORIGINAL prompt (the prompt
    isn't wrong, the budget is). Don't pollute messages with corrective
    follow-ups in this case."""
    seq = _SequencedChat(
        [_resp("", "length"), _resp('{"ok": 1}')]
    )
    chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        chat_fn=seq,
    )
    # Both attempts should use the same 2-message prompt.
    assert len(seq.calls[0]["messages"]) == 2
    assert len(seq.calls[1]["messages"]) == 2


# --------------------------------------------------------------------------- #
# JSON-parse retry
# --------------------------------------------------------------------------- #


def test_invalid_json_triggers_corrective_retry():
    seq = _SequencedChat(
        [
            _resp("not json at all"),
            _resp('{"recovered": true}'),
        ]
    )
    result = chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        chat_fn=seq, max_retries=2,
    )
    assert result.parsed == {"recovered": True}
    # Second call should include corrective follow-up about parser error.
    second_msgs = seq.calls[1]["messages"]
    assert len(second_msgs) == 4  # original 2 + assistant + corrective user
    assert "not valid JSON" in second_msgs[3]["content"]


def test_unrecoverable_invalid_json_raises_after_retries():
    seq = _SequencedChat([_resp("garbage one"), _resp("garbage two"), _resp("garbage three")])
    with pytest.raises(JsonCallError, match="exhausted retries"):
        chat_json(
            client=None, config=_cfg(),
            system="s", user="u",
            chat_fn=seq, max_retries=2,
        )


def test_strips_whitespace_around_json():
    seq = _SequencedChat([_resp('  \n  {"x": 1}  \n  ')])
    result = chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        chat_fn=seq,
    )
    assert result.parsed == {"x": 1}


# --------------------------------------------------------------------------- #
# Schema validation retry
# --------------------------------------------------------------------------- #


_SCHEMA = {
    "type": "object",
    "required": ["name", "age"],
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer"},
    },
    "additionalProperties": False,
}


def test_schema_validation_passes():
    seq = _SequencedChat([_resp('{"name": "lib", "age": 7}')])
    result = chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        schema=_SCHEMA,
        chat_fn=seq,
    )
    assert result.parsed == {"name": "lib", "age": 7}


def test_schema_violation_triggers_retry_with_validator_message():
    seq = _SequencedChat(
        [
            _resp('{"name": 1, "age": 7}'),         # name should be str
            _resp('{"name": "lib", "age": 7}'),     # corrected
        ]
    )
    result = chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        schema=_SCHEMA,
        chat_fn=seq, max_retries=2,
    )
    assert result.parsed["name"] == "lib"
    second_msgs = seq.calls[1]["messages"]
    assert any("validate" in m["content"] for m in second_msgs[2:])


def test_schema_violation_after_retries_raises_schema_error():
    seq = _SequencedChat([_resp('{"name": 1, "age": "x"}')] * 4)
    with pytest.raises(SchemaValidationError):
        chat_json(
            client=None, config=_cfg(),
            system="s", user="u",
            schema=_SCHEMA,
            chat_fn=seq, max_retries=2,
        )


# --------------------------------------------------------------------------- #
# Error from the underlying transport
# --------------------------------------------------------------------------- #


class _Boom:
    def __call__(self, *_a, **_k):
        raise ConnectionError("network down")


def test_transport_exception_wrapped_in_jsoncallerror():
    with pytest.raises(JsonCallError, match="network down") as exc_info:
        chat_json(
            client=None, config=_cfg(),
            system="s", user="u",
            chat_fn=_Boom(),
        )
    assert exc_info.value.attempts[0]["error"].startswith("ConnectionError")


# --------------------------------------------------------------------------- #
# Diagnostic trace
# --------------------------------------------------------------------------- #


def test_attempts_trace_records_each_step():
    seq = _SequencedChat(
        [
            _resp("", "length"),                # attempt 0
            _resp("not json"),                  # attempt 1
            _resp('{"ok": true}'),              # attempt 2
        ]
    )
    result = chat_json(
        client=None, config=_cfg(),
        system="s", user="u",
        chat_fn=seq, max_retries=3,
    )
    outcomes = [a["outcome"] for a in result.attempts]
    assert outcomes == ["length_truncated", "json_parse_error: Expecting value", "ok"]
