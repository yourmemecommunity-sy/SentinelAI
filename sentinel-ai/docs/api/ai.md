# AI Proxy API - *design; not implemented*

`POST /v1/ai/chat` and `POST /v1/ai/generate`:
1. Authenticate + resolve organization/policy.
2. Scan input (`direction=INPUT`). `BLOCK`/`QUARANTINE`/fail-closed -> `403 blocked` with `event_id`, no provider call.
3. Send **only `sanitized_text`** to the provider chosen by the router (`gemini | anthropic | openai | ollama`); unknown provider -> block.
4. Scan the response (`direction=OUTPUT`); sanitize or block; optionally de-tokenize when policy allows.
5. Record an audit-safe event; return the response.

**Status:** implemented for `gemini`, `openai`, `anthropic`, `ollama` (each present only if configured). Streaming responses are not exposed yet.

Provider adapters implement `AIProvider { chat, generate, stream, validate, getModels }`; the core never contains provider-specific logic.
Streaming responses are scanned incrementally with a hold-back window so a secret split across chunks is not released.
