"""LLM configuration loader.

Resolves provider URL, API key, model, temperature, and max-tokens
from the environment, with optional per-step overrides. ``.env`` is
loaded via ``python-dotenv`` if present so ``pytest`` and ``python -m
check_me`` work the same way during development.

Lookup precedence (highest first):

1. Explicit kwargs to ``load_config(...)``
2. Step-specific env var (e.g. ``CHECK_ME_LLM_MODEL_STEP2_VERIFIER``)
3. Generic env var (e.g. ``CHECK_ME_LLM_MODEL``)
4. ``.env`` file in the project root
5. Built-in default (only for non-secret knobs; URL/KEY/MODEL have no
   defaults and raise ``ConfigError`` if missing)

Why this design — see ``docs/LLM_CONFIG.md``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

try:  # python-dotenv is a dev convenience, not strictly required.
    from dotenv import load_dotenv as _load_dotenv
except ImportError:  # pragma: no cover - dependency declared in pyproject
    def _load_dotenv(*_args, **_kwargs) -> bool:
        return False


# --------------------------------------------------------------------------- #
# Step identity
# --------------------------------------------------------------------------- #


class StepKind(str, Enum):
    """The pipeline step a request originates from. Used to look up
    step-specific env-var overrides without hard-coding step names in
    the env-var lookup logic."""

    STEP2_MINER = "STEP2_MINER"
    STEP2_VERIFIER = "STEP2_VERIFIER"
    STEP3 = "STEP3"
    STEP4 = "STEP4"


# --------------------------------------------------------------------------- #
# Config dataclass
# --------------------------------------------------------------------------- #


class ConfigError(RuntimeError):
    """Raised when a required env var is missing or unparsable."""


@dataclass(frozen=True)
class Config:
    """Resolved LLM configuration for one call site.

    The fields are deliberately flat — the OpenAI SDK takes them as
    kwargs and any provider that speaks Chat Completions accepts the
    same shape.
    """

    url: str
    key: str
    model: str
    temperature: float
    max_tokens: int
    timeout_sec: float = 1800.0
    max_retries: int = 1

    def redacted(self) -> dict:
        """Return a dict safe to log: key replaced with a marker."""
        return {
            "url": self.url,
            "key": _redact_key(self.key),
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_sec": self.timeout_sec,
            "max_retries": self.max_retries,
        }


def _redact_key(k: str) -> str:
    if not k:
        return "<empty>"
    if len(k) <= 8:
        return "***"
    return f"{k[:4]}...{k[-4:]}"


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #


_ENV_VAR_DEFAULT = {
    "url": "CHECK_ME_LLM_URL",
    "key": "CHECK_ME_LLM_KEY",
    "model": "CHECK_ME_LLM_MODEL",
    "temperature": "CHECK_ME_LLM_TEMPERATURE",
    "max_tokens": "CHECK_ME_LLM_MAX_TOKENS",
    "timeout_sec": "CHECK_ME_LLM_TIMEOUT_SEC",
    "max_retries": "CHECK_ME_LLM_MAX_RETRIES",
}

_BUILTIN_DEFAULTS = {
    "temperature": "0.1",
    "max_tokens": "4096",
    # Per-request HTTP timeout for the OpenAI SDK call. Default 30
    # min — sized for ``reasoning_effort: "high"`` runs on long
    # prompts (Step 3 IR synthesis with N=2 hybrid retrieval, Step 4
    # holistic scenario synthesis with all IRs visible). The SDK
    # default of 600s (10 min) was tight enough that internal-LLM
    # runs at high reasoning timed out on the long calls and the SDK
    # auto-retried — burning prompt tokens without progress.
    "timeout_sec": "1800",
    # Number of OpenAI SDK auto-retries on transient errors per call.
    # Default 1 (was the SDK default of 2). Combined with the higher
    # per-request timeout above, worst-case time on a single call is
    # bounded at 2 * timeout_sec = 1 hour — still bounded, but with
    # fewer redundant retry attempts after a long real-time-out.
    "max_retries": "1",
}


def _project_root() -> Path:
    """Walk up from this file looking for a directory containing
    ``pyproject.toml``. Falls back to ``cwd`` if the marker isn't
    found within five levels — keeps unit-test fixtures honest."""
    p = Path(__file__).resolve()
    for _ in range(8):
        if (p / "pyproject.toml").is_file():
            return p
        if p.parent == p:
            break
        p = p.parent
    return Path.cwd()


def _load_dotenv_once() -> None:
    """Load ``.env`` from the project root the first time we are
    asked. Calling more than once is a no-op (dotenv handles that)."""
    env_path = _project_root() / ".env"
    if env_path.is_file():
        # ``override=False`` means env vars already set in the shell win
        # over .env — same convention as docker-compose, hashicorp etc.
        _load_dotenv(env_path, override=False)


def _resolve(
    field: str,
    step: StepKind | None,
    overrides: dict[str, object],
) -> str | None:
    """Walk the lookup precedence for one field. Returns None if the
    value cannot be resolved; the caller decides whether None is fatal."""
    if field in overrides and overrides[field] is not None:
        return str(overrides[field])
    base = _ENV_VAR_DEFAULT[field]
    if step is not None:
        step_var = f"{base}_{step.value}"
        v = os.environ.get(step_var)
        if v is not None and v != "":
            return v
    v = os.environ.get(base)
    if v is not None and v != "":
        return v
    if field in _BUILTIN_DEFAULTS:
        return _BUILTIN_DEFAULTS[field]
    return None


def load_config(
    *,
    step: StepKind | None = None,
    url: str | None = None,
    key: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    timeout_sec: float | None = None,
    max_retries: int | None = None,
) -> Config:
    """Resolve a ``Config`` from env vars + ``.env`` + explicit kwargs.

    Pass ``step`` to enable per-step env-var overrides
    (``CHECK_ME_LLM_MODEL_STEP2_VERIFIER`` etc.). Explicit kwargs win
    over env vars; missing required values raise ``ConfigError``.
    """
    _load_dotenv_once()
    overrides = {
        "url": url,
        "key": key,
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout_sec": timeout_sec,
        "max_retries": max_retries,
    }

    resolved_url = _resolve("url", step, overrides)
    resolved_key = _resolve("key", step, overrides)
    resolved_model = _resolve("model", step, overrides)

    if not resolved_url:
        raise ConfigError(
            "CHECK_ME_LLM_URL is not set. Copy .env.example to .env and"
            " fill in your provider's base URL, or pass url=... explicitly."
        )
    if not resolved_key:
        raise ConfigError("CHECK_ME_LLM_KEY is not set.")
    if not resolved_model:
        raise ConfigError("CHECK_ME_LLM_MODEL is not set.")

    raw_temp = _resolve("temperature", step, overrides)
    raw_max = _resolve("max_tokens", step, overrides)
    raw_timeout = _resolve("timeout_sec", step, overrides)
    raw_retries = _resolve("max_retries", step, overrides)
    try:
        resolved_temp = float(raw_temp)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"CHECK_ME_LLM_TEMPERATURE not a float: {raw_temp!r}"
        ) from exc
    try:
        resolved_max = int(raw_max)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"CHECK_ME_LLM_MAX_TOKENS not an int: {raw_max!r}"
        ) from exc
    try:
        resolved_timeout = float(raw_timeout)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"CHECK_ME_LLM_TIMEOUT_SEC not a float: {raw_timeout!r}"
        ) from exc
    try:
        resolved_retries = int(raw_retries)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"CHECK_ME_LLM_MAX_RETRIES not an int: {raw_retries!r}"
        ) from exc

    if resolved_max < 256:
        raise ConfigError(
            f"CHECK_ME_LLM_MAX_TOKENS={resolved_max} is too low — Gemini"
            " 2.5/3 thinking models need ~2000 minimum to leave any"
            " budget for visible output. Use 4096+ in dev."
        )
    if not (0.0 <= resolved_temp <= 2.0):
        raise ConfigError(
            f"CHECK_ME_LLM_TEMPERATURE={resolved_temp} out of typical range"
            " 0.0-2.0."
        )
    if resolved_timeout < 30:
        raise ConfigError(
            f"CHECK_ME_LLM_TIMEOUT_SEC={resolved_timeout} too low — at"
            " reasoning_effort=high a single Step 3 / Step 4 LLM call can"
            " take 5-30 minutes. Use 600+ for production, 30+ for tests."
        )
    if resolved_retries < 0:
        raise ConfigError(
            f"CHECK_ME_LLM_MAX_RETRIES={resolved_retries} must be >= 0."
        )

    return Config(
        url=resolved_url.rstrip("/"),
        key=resolved_key,
        model=resolved_model,
        temperature=resolved_temp,
        max_tokens=resolved_max,
        timeout_sec=resolved_timeout,
        max_retries=resolved_retries,
    )
