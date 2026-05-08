"""Thin wrapper around the OpenAI Python SDK.

Why a wrapper? Three reasons:
1. Consistent injection point for tests (mock this layer, not SDK
   internals).
2. A single place to log / cache / retry without polluting the rest
   of the codebase.
3. Future-proof: if we ever need to swap the SDK (e.g. for a
   provider that drifts away from OpenAI Chat Completions shape),
   only this module changes.

Two wire formats are supported:

- **Chat Completions** (``client.chat.completions.create``) — the
  long-standing format spoken by Gemini OpenAI-compat, Anthropic
  OpenAI-compat, OpenRouter, vLLM/TGI/Ollama, DashScope, and most
  GPT-4-family models.
- **Responses API** (``client.responses.create``) — the newer
  format used by OpenAI Codex / GPT-5 family. ``input`` replaces
  ``messages``, ``max_output_tokens`` replaces ``max_tokens``,
  ``reasoning={"effort": ...}`` replaces ``reasoning_effort``,
  and the response carries ``output[].content[]`` instead of
  ``choices[].message.content``.

``Config.api_mode`` selects between them: ``"auto"`` picks Responses
for Codex / GPT-5 model-name patterns and Chat Completions for
everything else; explicit ``"chat_completions"`` / ``"responses"``
override. ``ChatRequest`` and ``ChatResponse`` shapes stay format-
agnostic — Responses-API replies are flattened into the same
``ChatResponse`` fields so callers and tests don't need to branch
on wire format.
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
    so ``config.url`` is the base path *up to but not including* it.

    ``timeout`` and ``max_retries`` are sized for thinking-model
    runs at ``reasoning_effort: "high"`` — a single Step 3 / Step 4
    LLM call on a long-context prompt can legitimately take
    20-40 minutes, well beyond the SDK's 600s default. The previous
    default caused retry storms (each retry = 10min wasted) when
    internal-LLM calls genuinely needed longer to think. Both
    knobs are env-overridable via ``CHECK_ME_LLM_TIMEOUT_SEC`` /
    ``CHECK_ME_LLM_MAX_RETRIES``."""
    return OpenAI(
        base_url=config.url,
        api_key=config.key,
        timeout=config.timeout_sec,
        max_retries=config.max_retries,
    )


# --------------------------------------------------------------------------- #
# Wire-format helpers
# --------------------------------------------------------------------------- #


def _resolve_api_mode(config: Config) -> str:
    """Return ``"chat_completions"`` or ``"responses"`` for this call.

    ``config.api_mode`` is honoured when explicit. ``"auto"`` falls
    back to model-name heuristic: any model whose identifier contains
    ``"codex"`` (case-insensitive) routes to Responses API. The
    heuristic is anchored on a single, broadly published vendor
    convention — OpenAI's Codex / GPT-5 family is the only mass-
    market case where Responses API is the only supported wire
    format. Any other model — including self-hosted, Anthropic /
    Gemini OpenAI-compat, OpenRouter routes — is reachable via Chat
    Completions, so that is the safe default.
    """
    if config.api_mode in ("chat_completions", "responses"):
        return config.api_mode
    name = (config.model or "").lower()
    if "codex" in name:
        return "responses"
    return "chat_completions"


def _uses_chat_completion_tokens_param(model: str) -> bool:
    """True when the model's Chat Completions endpoint expects
    ``max_completion_tokens`` instead of ``max_tokens``.

    OpenAI's reasoning-tier models (``gpt-5*``, ``o3*``, ``o4*``)
    rejected the legacy ``max_tokens`` field after the API rename.
    The heuristic matches on canonical prefixes and is anchored to
    OpenAI's public model naming — no project-specific names.
    """
    name = (model or "").lower()
    return (
        name.startswith("gpt-5")
        or name.startswith("o3")
        or name.startswith("o4")
    )


def _is_reasoning_model_family(model: str) -> bool:
    """True when the model rejects an explicit ``temperature`` field.

    Reasoning-tier models (OpenAI ``gpt-5*`` / ``o3*`` / ``o4*`` /
    anything with ``codex`` in the name) ignore or reject explicit
    sampling temperature — they manage internal sampling for the
    reasoning pass. We strip the field client-side to avoid the API
    error rather than letting the SDK 400 on every call.
    """
    name = (model or "").lower()
    return (
        _uses_chat_completion_tokens_param(name)
        or "codex" in name
    )


def _flatten_responses_output(raw: dict, completion: Any) -> str:
    """Extract the visible text from a Responses-API completion.

    Responses returns a structured ``output[]`` list whose entries
    contain ``content[]`` items of various ``type``s; only items
    with ``type == "output_text"`` carry user-visible text. The SDK
    also exposes a convenience accessor ``completion.output_text``
    on the live object — we honour it as the primary path and fall
    back to walking the dict shape so the function works against
    canned dict fixtures as well as live SDK objects.
    """
    text = getattr(completion, "output_text", None)
    if isinstance(text, str) and text:
        return text
    chunks: list[str] = []
    for item in raw.get("output") or []:
        for part in item.get("content") or []:
            if part.get("type") == "output_text":
                value = part.get("text") or ""
                if value:
                    chunks.append(value)
    return "".join(chunks)


def _flatten_responses_finish_reason(raw: dict) -> str:
    """Map Responses-API status fields onto a Chat-Completions-style
    ``finish_reason``.

    Priority: ``incomplete_details.reason`` (e.g. ``"max_output_tokens"``,
    ``"content_filter"``) → top-level ``status`` (``"completed"`` →
    ``"stop"``, otherwise the raw value) → ``"<unknown>"``. The
    mapping preserves whatever truncation signal Responses provided
    so ``json_call.py``'s length-retry path triggers correctly.
    """
    incomplete = raw.get("incomplete_details") or {}
    reason = incomplete.get("reason") if isinstance(incomplete, dict) else None
    if reason:
        return str(reason)
    status = raw.get("status")
    if status == "completed":
        return "stop"
    if status:
        return str(status)
    return "<unknown>"


def _flatten_responses_usage(raw: dict) -> tuple[int, int, int]:
    """Translate Responses-API token usage into the Chat-Completions
    field names the rest of the pipeline expects.

    Responses returns ``input_tokens`` / ``output_tokens`` /
    ``total_tokens`` while Chat Completions uses ``prompt_tokens`` /
    ``completion_tokens`` / ``total_tokens``. Returning a flat tuple
    keeps the call site shape-agnostic.
    """
    usage = raw.get("usage") or {}
    prompt = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    completion = int(
        usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
    )
    total = int(usage.get("total_tokens", prompt + completion) or 0)
    return prompt, completion, total


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
    """Issue a single LLM call using ``client`` and the knobs from
    ``config``. Returns a flattened ``ChatResponse``.

    The wire format is selected by ``_resolve_api_mode(config)``:
    Chat Completions or Responses API (see module docstring).
    Both branches share the rate-limit retry loop and the
    ``ChatResponse`` shape — only the request kwargs and the
    response-flattening differ.

    Handles HTTP 429 ``RateLimitError`` with provider-aware backoff:
    parses the retry hint from the error body when available
    (Gemini's OpenAI-compat embeds ``retryDelay: <Ns>``), waits, and
    retries up to ``RATE_LIMIT_MAX_RETRIES``. Other transient errors
    are left to the OpenAI SDK's own retry mechanism. JSON parsing
    and schema validation live in ``json_call.py``.
    """
    api_mode = _resolve_api_mode(config)
    is_reasoning = _is_reasoning_model_family(config.model)

    if api_mode == "responses":
        kwargs: dict[str, Any] = {
            "model": config.model,
            "input": request.messages,
            "max_output_tokens": config.max_tokens,
        }
        if not is_reasoning:
            kwargs["temperature"] = config.temperature
        if request.json_object:
            kwargs["text"] = {"format": {"type": "json_object"}}
        # Merge caller-provided extras with field-name remapping so
        # the rest of the pipeline can keep using the Chat-Completions
        # vocabulary (``max_tokens`` / ``reasoning_effort``) without
        # caring which wire format is in play.
        for k, v in request.extra.items():
            if k == "max_tokens":
                kwargs["max_output_tokens"] = v
            elif k == "reasoning_effort":
                kwargs["reasoning"] = {"effort": v}
            else:
                kwargs[k] = v
        if is_reasoning:
            kwargs.pop("temperature", None)
        create_call = client.responses.create
    else:
        kwargs = {
            "model": config.model,
            "messages": request.messages,
        }
        if not is_reasoning:
            kwargs["temperature"] = config.temperature
        # OpenAI reasoning-tier Chat Completions endpoint expects
        # ``max_completion_tokens``; legacy models still use
        # ``max_tokens``. The split was made by OpenAI; we mirror it.
        token_field = (
            "max_completion_tokens"
            if _uses_chat_completion_tokens_param(config.model)
            else "max_tokens"
        )
        kwargs[token_field] = config.max_tokens
        if request.json_object:
            kwargs["response_format"] = {"type": "json_object"}
        # Same field-rename treatment for caller extras.
        for k, v in request.extra.items():
            if k == "max_tokens" and token_field == "max_completion_tokens":
                kwargs["max_completion_tokens"] = v
            else:
                kwargs[k] = v
        if is_reasoning:
            kwargs.pop("temperature", None)
        create_call = client.chat.completions.create

    total_waited = 0.0
    attempt = 0
    while True:
        try:
            completion = create_call(**kwargs)
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
    if api_mode == "responses":
        prompt_tokens, completion_tokens, total_tokens = _flatten_responses_usage(
            raw
        )
        return ChatResponse(
            content=_flatten_responses_output(raw, completion),
            finish_reason=_flatten_responses_finish_reason(raw),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=raw.get("model", config.model),
            raw=raw,
        )
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
