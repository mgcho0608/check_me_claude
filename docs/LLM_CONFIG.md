# LLM provider configuration

Check Me's Steps 2/3/4 talk to an LLM. The wire format is the
**OpenAI Chat Completions API** — any provider that speaks it plugs
in via three env vars. No code branches on provider.

## Three env vars (the contract)

| Variable | Purpose |
|---|---|
| `CHECK_ME_LLM_URL` | Provider base URL up to (but not including) `/chat/completions` |
| `CHECK_ME_LLM_KEY` | Provider API key (treat as a secret) |
| `CHECK_ME_LLM_MODEL` | Model identifier as the provider expects it |

Two more, with sensible defaults:

| Variable | Default | Notes |
|---|---|---|
| `CHECK_ME_LLM_TEMPERATURE` | `0.1` | 0.0 for verifier (no creativity), 0.1 for proposer |
| `CHECK_ME_LLM_MAX_TOKENS` | `4096` | Must cover thinking budget on Gemini 2.5/3; <2048 risks empty content |

`.env` is loaded automatically when the project's `pyproject.toml`
is reachable. In production the values come from the deploy
environment; `python-dotenv` stays out of the way.

## Quick setup

```sh
cp .env.example .env
# edit .env with your provider/key/model
```

That's it. `pytest` and `python -m check_me ...` both pick the
config up.

## Provider matrix

All four providers below speak OpenAI Chat Completions. You change
the URL + KEY + MODEL — nothing else.

### Google Gemini (development default)

```
CHECK_ME_LLM_URL=https://generativelanguage.googleapis.com/v1beta/openai
CHECK_ME_LLM_KEY=AIza...         # Google AI Studio key
CHECK_ME_LLM_MODEL=gemini-3-flash-preview
CHECK_ME_LLM_TEMPERATURE=0.1
CHECK_ME_LLM_MAX_TOKENS=4096
```

Notes:
- Reachable from the development sandbox (other providers are
  blocked at the host-allowlist layer).
- Gemini 2.5/3 is a *thinking* model — thinking tokens count
  against `max_tokens`. **Keep `max_tokens` ≥ 2048**, ideally
  4096–8192. Below that the model may spend its whole budget on
  internal reasoning and return empty content with
  `finish_reason="length"`.
- JSON mode (`response_format={"type":"json_object"}`) is
  supported and verified by `tests/test_llm_smoke.py`.

### OpenRouter (production target)

```
CHECK_ME_LLM_URL=https://openrouter.ai/api/v1
CHECK_ME_LLM_KEY=sk-or-v1-...
CHECK_ME_LLM_MODEL=qwen/qwen3.6-27b
```

Recommended provider for the deployment-target Qwen3.6 27B model.
The OpenRouter URL routes to multiple backends (DeepInfra,
Alibaba Cloud, etc.); they negotiate cheapest/fastest.

### Anthropic (alternative dev — OpenAI-compat shim)

```
CHECK_ME_LLM_URL=https://api.anthropic.com/v1
CHECK_ME_LLM_KEY=sk-ant-...
CHECK_ME_LLM_MODEL=claude-haiku-4-5
```

JSON mode support depends on the shim's current version — verify
with `CHECK_ME_LIVE_LLM=1 pytest tests/test_llm_smoke.py` before
relying on it.

### Self-hosted (vLLM, TGI, Ollama, llama.cpp server)

```
CHECK_ME_LLM_URL=http://localhost:8000/v1
CHECK_ME_LLM_KEY=anything-non-empty
CHECK_ME_LLM_MODEL=qwen3.6-27b
```

For self-hosted Qwen on a GPU box, point `CHECK_ME_LLM_URL` at
your inference server. The Apache 2.0 license on Qwen3.6 27B
makes this fully legal.

## Per-step overrides

Each pipeline step can pin its own model + temperature without
touching the rest. Looked up before the generic vars:

```
CHECK_ME_LLM_MODEL_STEP2_MINER=gemini-3-flash-preview
CHECK_ME_LLM_MODEL_STEP2_VERIFIER=gemini-3-flash-preview
CHECK_ME_LLM_TEMPERATURE_STEP2_MINER=0.1
CHECK_ME_LLM_TEMPERATURE_STEP2_VERIFIER=0.0
```

Step kinds: `STEP2_MINER`, `STEP2_VERIFIER`, `STEP3`, `STEP4`.

Useful patterns:

- Cheaper model on miner, more capable on verifier
- Strict deterministic verifier (`temperature=0.0`)
- Two completely different vendors (e.g. miner on Gemini, verifier
  on Qwen) — wire format is the same, env var swap suffices.

## Determinism + reproducibility

- Set `temperature=0.0` for the verifier — same input should
  produce the same verdict.
- Provider-side seed support varies; trust the temperature for now.
- Every `chat_json` call records a `attempts` trace with finish
  reason, token counts, and outcome. Steps 2/3/4 will log these
  to `out/llm_log/` so a run is reproducible from its trace.

## Robust JSON output

`check_me.llm.json_call.chat_json` enforces JSON output with
three retry kinds:

1. **`finish_reason="length"`** — the model ran out of budget.
   Retry doubles `max_tokens` (capped at `max_tokens_ceiling`,
   default 8192). Same prompt; the prompt isn't wrong, the
   budget was.
2. **`json.loads` failed** — content is non-empty but malformed
   JSON. Retry with a corrective follow-up that pastes the
   parser error and asks for valid JSON only.
3. **Schema validation failed** — JSON parsed but the supplied
   `jsonschema` schema rejects it. Retry with a follow-up that
   pastes the validator error and a JSON pointer to the offending
   path.

Default `max_retries=2`. The aim is robustness against transient
hiccups, **not** iterative prompt repair — if a prompt
consistently yields invalid output, that's a prompt bug.

## Testing

| File | Purpose | Network? |
|---|---|---|
| `tests/test_llm_config.py` | Config resolution / precedence / errors | offline |
| `tests/test_llm_client.py` | OpenAI SDK wrapper request shape, response flattening | offline (SDK call mocked) |
| `tests/test_llm_json_call.py` | Retry on length / parse / schema | offline (chat_fn stubbed) |
| `tests/test_llm_smoke.py` | Real provider connectivity + JSON mode + schema flow | live, gated by `CHECK_ME_LIVE_LLM=1` |

Run the offline three on every commit; the live one only when
config or prompts change.

## Security notes

- `.env` is in `.gitignore`. Don't commit it.
- The key is redacted in `Config.redacted()` so logs never leak
  it.
- If you paste a key into a chat (e.g. when asking for help),
  rotate the key afterward — chat histories are persistent.
