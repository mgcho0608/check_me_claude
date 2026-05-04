"""LLM client layer for Steps 2/3/4.

Single thin abstraction around the OpenAI Chat Completions wire format.
Any provider that speaks it (Google Gemini OpenAI-compat, OpenRouter,
Anthropic OpenAI-compat shim, self-hosted vLLM/TGI/Ollama, …) plugs in
via three env vars: ``CHECK_ME_LLM_URL``, ``CHECK_ME_LLM_KEY``,
``CHECK_ME_LLM_MODEL``. See ``docs/LLM_CONFIG.md``.

The deploy-time swap is therefore three env-var changes; no code path
branches on provider.
"""

from .config import (
    Config,
    StepKind,
    load_config,
)
from .client import make_client, ChatRequest, ChatResponse
from .json_call import (
    JsonCallError,
    SchemaValidationError,
    chat_json,
)

__all__ = [
    "Config",
    "StepKind",
    "load_config",
    "make_client",
    "ChatRequest",
    "ChatResponse",
    "JsonCallError",
    "SchemaValidationError",
    "chat_json",
]
