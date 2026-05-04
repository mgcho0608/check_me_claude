"""JSON-output LLM call with schema validation and retry.

Steps 2/3/4 all need the same thing: a chat completion that returns a
JSON object validating against a known JSON schema. ``chat_json``
encapsulates that pattern with three retry kinds:

1. Provider returned ``finish_reason='length'`` (truncated). Retry
   once with ``max_tokens`` doubled — only if the original budget
   was below a sensible ceiling (8192 by default).
2. Returned non-empty content but ``json.loads`` failed. Retry with a
   "your previous output was not valid JSON; here is the parser
   error: …" follow-up message appended.
3. JSON parsed but ``jsonschema.validate`` failed. Retry with the
   validator error appended.

The retry budget is small (default 2 retries total). The goal is
robustness against transient hiccups, not iterative repair — if the
model consistently produces bad output for a given prompt that's a
prompt-engineering bug, not a runtime issue.

Design constraint: the function must be testable without a real
network. The OpenAI client (or any duck-typed substitute) is passed
in by the caller; tests pass a ``StubClient`` that returns canned
``ChatResponse`` objects in sequence.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

import jsonschema

from .client import ChatRequest, ChatResponse, chat
from .config import Config

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class JsonCallError(RuntimeError):
    """A chat_json call failed after all retries.

    ``attempts`` carries the per-attempt diagnostic so callers can log
    a structured trace without re-running.
    """

    def __init__(self, message: str, attempts: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.attempts = attempts


class SchemaValidationError(JsonCallError):
    """Final attempt's JSON parsed but did not match the schema."""


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


@dataclass
class CallResult:
    parsed: dict[str, Any]
    response: ChatResponse
    attempts: list[dict[str, Any]]


def chat_json(
    client: Any,
    config: Config,
    *,
    system: str,
    user: str,
    schema: dict[str, Any] | None = None,
    max_retries: int = 2,
    max_tokens_ceiling: int = 8192,
    extra_request: dict[str, Any] | None = None,
    chat_fn: Callable[[Any, Config, ChatRequest], ChatResponse] = chat,
) -> CallResult:
    """Issue a JSON-mode chat completion with retry on length /
    parse / schema errors.

    Parameters
    ----------
    client
        Anything with the OpenAI SDK shape — ``client.chat.completions
        .create(...)``. Production: ``make_client(config)``. Tests:
        a stub.
    config
        Provider knobs (URL/KEY/MODEL/temperature/max_tokens).
    system, user
        Standard chat roles. Combined into a 2-message conversation.
    schema
        Optional JSON Schema; if provided, the parsed JSON is
        validated against it. Validation failure triggers a retry.
    max_retries
        Number of *additional* attempts after the initial one. Total
        attempts = ``1 + max_retries``.
    max_tokens_ceiling
        Cap for the ``max_tokens`` doubling on length-finish retries.
    extra_request
        Provider-specific knobs forwarded as ``ChatRequest.extra`` on
        every attempt (e.g. ``{"reasoning_effort": "low"}`` to bound
        Gemini's thinking budget on token-heavy prompts so visible
        output isn't squeezed out).
    chat_fn
        Override only for tests — production code should never need
        this.

    Returns
    -------
    CallResult
        ``parsed`` is the validated JSON object; ``response`` is the
        provider's last raw response; ``attempts`` is a diagnostic
        list (one dict per attempt).
    """
    base_messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    attempts: list[dict[str, Any]] = []

    cur_max_tokens = config.max_tokens
    follow_ups: list[dict[str, str]] = []

    for attempt_idx in range(max_retries + 1):
        request = ChatRequest(
            messages=base_messages + follow_ups,
            json_object=True,
        )
        if extra_request:
            request.extra.update(extra_request)
        # Inject a possibly-bumped max_tokens via extra so we don't
        # mutate the shared config dataclass.
        if cur_max_tokens != config.max_tokens:
            request.extra["max_tokens"] = cur_max_tokens

        attempt_record: dict[str, Any] = {
            "attempt": attempt_idx,
            "max_tokens": cur_max_tokens,
            "follow_ups": list(follow_ups),
        }

        # Effective config for this attempt — bump max_tokens if needed.
        eff_config = (
            config
            if cur_max_tokens == config.max_tokens
            else _with_max_tokens(config, cur_max_tokens)
        )

        try:
            response = chat_fn(client, eff_config, request)
        except Exception as exc:  # noqa: BLE001 - propagate after recording
            attempt_record["error"] = f"{type(exc).__name__}: {exc}"
            attempts.append(attempt_record)
            raise JsonCallError(
                f"LLM call raised on attempt {attempt_idx}: {exc!r}",
                attempts,
            ) from exc

        attempt_record.update(
            finish_reason=response.finish_reason,
            tokens=response.total_tokens,
            content_len=len(response.content),
        )

        # 1. Truncated -> bump and retry.
        if response.finish_reason == "length":
            attempt_record["outcome"] = "length_truncated"
            attempts.append(attempt_record)
            if cur_max_tokens >= max_tokens_ceiling:
                raise JsonCallError(
                    "Hit max_tokens ceiling and provider still returned"
                    f" finish_reason=length after {attempt_idx + 1} attempts.",
                    attempts,
                )
            cur_max_tokens = min(cur_max_tokens * 2, max_tokens_ceiling)
            follow_ups = []  # length retry uses original prompt
            continue

        # 2. Try to parse JSON.
        content = response.content.strip()
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            attempt_record["outcome"] = f"json_parse_error: {exc.msg}"
            attempts.append(attempt_record)
            follow_ups = [
                {
                    "role": "assistant",
                    "content": content,
                },
                {
                    "role": "user",
                    "content": (
                        "Your previous response was not valid JSON. Parser"
                        f" error: {exc.msg!r} at position {exc.pos}. Reply"
                        " with a single valid JSON object only — no prose,"
                        " no markdown fences."
                    ),
                },
            ]
            cur_max_tokens = config.max_tokens
            continue

        # 3. Schema validation if requested.
        if schema is not None:
            try:
                jsonschema.validate(parsed, schema)
            except jsonschema.ValidationError as exc:
                attempt_record["outcome"] = f"schema_error: {exc.message[:200]}"
                attempts.append(attempt_record)
                follow_ups = [
                    {"role": "assistant", "content": content},
                    {
                        "role": "user",
                        "content": (
                            "Your previous JSON did not validate against"
                            " the required schema. Validator error:"
                            f" {exc.message!r}. Path: {list(exc.absolute_path)!r}."
                            " Fix and reply with a single valid JSON"
                            " object only."
                        ),
                    },
                ]
                cur_max_tokens = config.max_tokens
                continue

        # Success.
        attempt_record["outcome"] = "ok"
        attempts.append(attempt_record)
        return CallResult(parsed=parsed, response=response, attempts=attempts)

    # Exhausted retries.
    last = attempts[-1]
    if last.get("outcome", "").startswith("schema_error"):
        raise SchemaValidationError(
            f"Schema validation failed after {len(attempts)} attempts."
            f" Last error: {last['outcome']}",
            attempts,
        )
    raise JsonCallError(
        f"chat_json exhausted retries ({len(attempts)} attempts);"
        f" last outcome: {last.get('outcome', '?')}",
        attempts,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _with_max_tokens(config: Config, new_max: int) -> Config:
    """Return a copy of ``config`` with a bumped ``max_tokens``."""
    from dataclasses import replace

    return replace(config, max_tokens=new_max)
