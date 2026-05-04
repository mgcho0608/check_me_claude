"""Thin wrapper around the OpenAI Python SDK.

Why a wrapper? Three reasons:
1. Consistent injection point for tests (mock this layer, not SDK
   internals).
2. A single place to log / cache / retry without polluting the rest
   of the codebase.
3. Future-proof: if we ever need to swap the SDK (e.g. for a
   provider that drifts away from OpenAI Chat Completions shape),
   only this module changes.

The wire format is OpenAI Chat Completions. ``ChatRequest`` carries
exactly what an OpenAI client wants; ``ChatResponse`` carries what
we want back (content + finish_reason + token usage). Provider
quirks (Gemini's thinking-token consumption, Anthropic's response
shape variations) surface naturally through these fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

from .config import Config


# --------------------------------------------------------------------------- #
# Request / response shapes
# --------------------------------------------------------------------------- #


@dataclass
class ChatRequest:
    messages: list[dict[str, str]]
    json_object: bool = False
    """If True, set ``response_format={'type':'json_object'}``. Provider
    must support it; Gemini's OpenAI-compat does, Anthropic's may not."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Provider-specific knobs passed through verbatim
    (``reasoning_effort``, ``stop``, ``seed`` …). Keep small."""


@dataclass
class ChatResponse:
    content: str
    finish_reason: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    model: str
    raw: dict[str, Any]
    """Untouched response dict — useful for tests and debugging."""


# --------------------------------------------------------------------------- #
# Client factory + chat call
# --------------------------------------------------------------------------- #


def make_client(config: Config) -> OpenAI:
    """Construct an OpenAI SDK client pointed at the configured
    provider. The SDK appends the ``/chat/completions`` path itself,
    so ``config.url`` is the base path *up to but not including* it."""
    return OpenAI(base_url=config.url, api_key=config.key)


def chat(client: OpenAI, config: Config, request: ChatRequest) -> ChatResponse:
    """Issue a single Chat Completions call using ``client`` and the
    knobs from ``config``. Returns a flattened ``ChatResponse``.

    No retry, no JSON parsing, no schema validation — those live in
    ``json_call.py``. Keep this function dumb.
    """
    kwargs: dict[str, Any] = {
        "model": config.model,
        "messages": request.messages,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    if request.json_object:
        kwargs["response_format"] = {"type": "json_object"}
    kwargs.update(request.extra)

    completion = client.chat.completions.create(**kwargs)
    raw = completion.model_dump()
    choice = raw["choices"][0]
    msg = choice.get("message") or {}
    content = msg.get("content") or ""
    usage = raw.get("usage") or {}
    return ChatResponse(
        content=content,
        finish_reason=choice.get("finish_reason", "<unknown>"),
        prompt_tokens=int(usage.get("prompt_tokens", 0)),
        completion_tokens=int(usage.get("completion_tokens", 0)),
        total_tokens=int(usage.get("total_tokens", 0)),
        model=raw.get("model", config.model),
        raw=raw,
    )
