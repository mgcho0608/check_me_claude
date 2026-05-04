"""Pytest for check_me.llm.config — pure logic, no network."""

from __future__ import annotations

import os

import pytest

from check_me.llm.config import (
    Config,
    ConfigError,
    StepKind,
    load_config,
)


# --------------------------------------------------------------------------- #
# Fixture: clean env so .env in the repo doesn't leak in
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Drop any CHECK_ME_LLM_ vars set in the shell so each test
    starts with a known empty environment. Also disable the ``.env``
    auto-loader — otherwise the repo's own .env (development key)
    would leak into tests of "missing var" behaviour."""
    for k in list(os.environ):
        if k.startswith("CHECK_ME_LLM_"):
            monkeypatch.delenv(k, raising=False)
    # Suppress the dotenv loader inside check_me.llm.config so the
    # repo's .env doesn't repopulate the env we just cleared.
    import check_me.llm.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "_load_dotenv_once", lambda: None)
    yield


def _set_minimum(monkeypatch):
    monkeypatch.setenv("CHECK_ME_LLM_URL", "https://example.test/v1")
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "k-abc-1234")
    monkeypatch.setenv("CHECK_ME_LLM_MODEL", "test-model-xl")


# --------------------------------------------------------------------------- #
# Required fields
# --------------------------------------------------------------------------- #


def test_load_config_with_minimum_env_vars(monkeypatch):
    _set_minimum(monkeypatch)
    cfg = load_config()
    assert cfg.url == "https://example.test/v1"
    assert cfg.key == "k-abc-1234"
    assert cfg.model == "test-model-xl"


def test_url_trailing_slash_stripped(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_URL", "https://example.test/v1/")
    cfg = load_config()
    assert cfg.url == "https://example.test/v1"


def test_missing_url_raises(monkeypatch):
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "k")
    monkeypatch.setenv("CHECK_ME_LLM_MODEL", "m")
    with pytest.raises(ConfigError, match="URL"):
        load_config()


def test_missing_key_raises(monkeypatch):
    monkeypatch.setenv("CHECK_ME_LLM_URL", "u")
    monkeypatch.setenv("CHECK_ME_LLM_MODEL", "m")
    with pytest.raises(ConfigError, match="KEY"):
        load_config()


def test_missing_model_raises(monkeypatch):
    monkeypatch.setenv("CHECK_ME_LLM_URL", "u")
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "k")
    with pytest.raises(ConfigError, match="MODEL"):
        load_config()


def test_empty_string_treated_as_unset(monkeypatch):
    monkeypatch.setenv("CHECK_ME_LLM_URL", "u")
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "")
    monkeypatch.setenv("CHECK_ME_LLM_MODEL", "m")
    with pytest.raises(ConfigError, match="KEY"):
        load_config()


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #


def test_default_temperature_and_max_tokens(monkeypatch):
    _set_minimum(monkeypatch)
    cfg = load_config()
    assert cfg.temperature == 0.1
    assert cfg.max_tokens == 4096


def test_temperature_override_via_env(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_TEMPERATURE", "0.5")
    cfg = load_config()
    assert cfg.temperature == 0.5


def test_max_tokens_override_via_env(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_MAX_TOKENS", "8192")
    cfg = load_config()
    assert cfg.max_tokens == 8192


def test_temperature_out_of_range_rejected(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_TEMPERATURE", "3.5")
    with pytest.raises(ConfigError, match="TEMPERATURE"):
        load_config()


def test_max_tokens_too_low_rejected(monkeypatch):
    """Below 256 the floor we set; Gemini 2.5/3 thinking budget alone
    eats more than that."""
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_MAX_TOKENS", "100")
    with pytest.raises(ConfigError, match="too low"):
        load_config()


def test_temperature_unparsable_raises(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_TEMPERATURE", "warm")
    with pytest.raises(ConfigError, match="TEMPERATURE"):
        load_config()


def test_max_tokens_unparsable_raises(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_MAX_TOKENS", "many")
    with pytest.raises(ConfigError, match="MAX_TOKENS"):
        load_config()


# --------------------------------------------------------------------------- #
# Per-step overrides
# --------------------------------------------------------------------------- #


def test_step_specific_model_overrides_generic(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_MODEL_STEP2_VERIFIER", "verifier-special")
    cfg_default = load_config()
    cfg_verifier = load_config(step=StepKind.STEP2_VERIFIER)
    assert cfg_default.model == "test-model-xl"
    assert cfg_verifier.model == "verifier-special"


def test_step_specific_temperature_overrides(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_TEMPERATURE_STEP2_VERIFIER", "0.0")
    cfg = load_config(step=StepKind.STEP2_VERIFIER)
    assert cfg.temperature == 0.0


def test_step_override_falls_back_to_generic(monkeypatch):
    """If the step-specific var isn't set, fall back to the generic one."""
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_TEMPERATURE", "0.7")
    cfg = load_config(step=StepKind.STEP2_VERIFIER)
    assert cfg.temperature == 0.7


# --------------------------------------------------------------------------- #
# Explicit kwarg precedence
# --------------------------------------------------------------------------- #


def test_explicit_kwargs_win_over_env(monkeypatch):
    _set_minimum(monkeypatch)
    cfg = load_config(model="kwarg-model", temperature=0.0)
    assert cfg.model == "kwarg-model"
    assert cfg.temperature == 0.0
    # Untouched fields still come from env.
    assert cfg.url == "https://example.test/v1"


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def test_redacted_hides_full_key(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "AIza-very-secret-key-123456")
    cfg = load_config()
    out = cfg.redacted()
    assert "AIza" in out["key"]
    assert "3456" in out["key"]
    assert "secret" not in out["key"]
    assert "..." in out["key"]


def test_redacted_short_key(monkeypatch):
    _set_minimum(monkeypatch)
    monkeypatch.setenv("CHECK_ME_LLM_KEY", "short")
    cfg = load_config()
    assert cfg.redacted()["key"] == "***"
