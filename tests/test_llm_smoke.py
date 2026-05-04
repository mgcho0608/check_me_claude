"""Live LLM smoke tests — gated behind ``CHECK_ME_LIVE_LLM=1``.

These tests issue real API calls. They are off by default so:

- ``pytest`` runs offline + free for everyone (CI, contributors,
  pre-commit hooks).
- The dev-time signal "is the configured provider actually
  reachable + producing usable JSON?" is reproducible by setting
  one env var.

To run::

    CHECK_ME_LIVE_LLM=1 pytest tests/test_llm_smoke.py -v

The ``.env`` in the project root is loaded automatically — make sure
``CHECK_ME_LLM_URL/KEY/MODEL`` are set there or in the shell.
"""

from __future__ import annotations

import json
import os

import pytest

from check_me.llm import (
    chat_json,
    load_config,
    make_client,
)
from check_me.llm.client import ChatRequest, chat


_LIVE = os.environ.get("CHECK_ME_LIVE_LLM") == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="set CHECK_ME_LIVE_LLM=1 to run live-API smoke tests",
)


# --------------------------------------------------------------------------- #
# Smoke 1: connectivity + auth + basic chat completion
# --------------------------------------------------------------------------- #


def test_live_chat_completion_works():
    cfg = load_config()
    client = make_client(cfg)
    resp = chat(
        client, cfg,
        ChatRequest(messages=[{"role": "user", "content": "Reply with the single word OK."}]),
    )
    # We don't pin exact content — Gemini may add punctuation, etc.
    # Just assert finish + non-zero usage.
    assert resp.finish_reason == "stop", (
        f"expected stop, got {resp.finish_reason!r}; if this is 'length',"
        " bump CHECK_ME_LLM_MAX_TOKENS — Gemini 2.5/3 thinking tokens"
        " count against the budget."
    )
    assert resp.total_tokens > 0
    assert resp.content.strip(), "model returned empty content"


# --------------------------------------------------------------------------- #
# Smoke 2: JSON mode produces parseable JSON
# --------------------------------------------------------------------------- #


def test_live_json_mode_returns_parseable():
    cfg = load_config()
    client = make_client(cfg)
    result = chat_json(
        client, cfg,
        system="You output strict JSON only. No prose, no markdown fences.",
        user='Return a JSON object with two fields: status="ok" and counter=42. Nothing else.',
    )
    assert isinstance(result.parsed, dict)
    assert result.parsed.get("status") == "ok"
    assert result.parsed.get("counter") == 42
    assert result.attempts[-1]["outcome"] == "ok"


# --------------------------------------------------------------------------- #
# Smoke 3: schema validation actually catches the model's mistake and
#          the retry loop recovers
# --------------------------------------------------------------------------- #


_SCHEMA = {
    "type": "object",
    "required": ["letters", "count"],
    "properties": {
        "letters": {"type": "array", "items": {"type": "string"}},
        "count": {"type": "integer"},
    },
    "additionalProperties": False,
}


def test_live_schema_validation_runs():
    cfg = load_config()
    client = make_client(cfg)
    result = chat_json(
        client, cfg,
        system="You output strict JSON only.",
        user=(
            "Return a JSON object. Required fields: 'letters' (array of"
            " three lowercase strings 'a', 'b', 'c'), 'count' (integer 3)."
            " No additional properties."
        ),
        schema=_SCHEMA,
    )
    assert result.parsed["count"] == 3
    assert result.parsed["letters"] == ["a", "b", "c"]
