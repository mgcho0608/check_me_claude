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

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI, RateLimitError

from .config import Config

logger = logging.getLogger(__name__)


# Maximum total wait, in seconds, that ``chat`` will spend retrying
# 429 RateLimitError. Beyond this it gives up and lets the error
# propagate. 600s = 10 min covers most published per-minute quotas.
RATE_LIMIT_MAX_TOTAL_WAIT = 600

# Number of 429 retries to attempt before giving up.
RATE_LIMIT_MAX_RETRIES = 6

# Floor wait between 429 retries when the provider doesn't include
# a RetryInfo hint (or the hint can't be parsed). Exponential backoff
# is applied on top of this floor.
RATE_LIMIT_DEFAULT_BACKOFF = 5.0


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


_RETRY_DELAY_RE = re.compile(
    r"['\"]retryDelay['\"]\s*:\s*['\"](\d+)s['\"]"
)


def _parse_rate_limit_wait(err: RateLimitError) -> float:
    """Best-effort extract of the provider's suggested retry delay
    from a RateLimitError. Gemini's OpenAI-compat encodes a
    ``retryDelay: <Ns>`` blob in the error body; if we can't find
    one, fall back to ``RATE_LIMIT_DEFAULT_BACKOFF``."""
    msg = str(err)
    m = _RETRY_DELAY_RE.search(msg)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return RATE_LIMIT_DEFAULT_BACKOFF


def chat(client: OpenAI, config: Config, request: ChatRequest) -> ChatResponse:
    """Issue a single Chat Completions call using ``client`` and the
    knobs from ``config``. Returns a flattened ``ChatResponse``.

    Handles HTTP 429 ``RateLimitError`` with provider-aware backoff:
    parses the retry hint from the error body when available
    (Gemini's OpenAI-compat embeds ``retryDelay: <Ns>``), waits, and
    retries up to ``RATE_LIMIT_MAX_RETRIES``. Other transient errors
    are left to the OpenAI SDK's own retry mechanism. JSON parsing
    and schema validation live in ``json_call.py``.
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

    total_waited = 0.0
    attempt = 0
    while True:
        try:
            completion = client.chat.completions.create(**kwargs)
            break
        except RateLimitError as exc:
            attempt += 1
            if attempt > RATE_LIMIT_MAX_RETRIES:
                logger.warning(
                    "chat: 429 retry budget exhausted (%d attempts, %.1fs total)",
                    attempt - 1, total_waited,
                )
                raise
            base_wait = _parse_rate_limit_wait(exc)
            # Exponential backoff factor on top of the parsed hint —
            # caps at 2x the hint to avoid waiting indefinitely if the
            # provider keeps returning short hints under sustained load.
            wait = min(base_wait * (1.5 ** (attempt - 1)), base_wait * 2)
            if total_waited + wait > RATE_LIMIT_MAX_TOTAL_WAIT:
                logger.warning(
                    "chat: 429 total-wait budget would exceed %ds; giving up",
                    RATE_LIMIT_MAX_TOTAL_WAIT,
                )
                raise
            logger.info(
                "chat: 429 backoff attempt %d, waiting %.1fs (total %.1fs)",
                attempt, wait, total_waited + wait,
            )
            time.sleep(wait)
            total_waited += wait
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
