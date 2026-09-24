# Provider verification matrix

Updated **2026-09-24**. A cell is only marked verified if that exact thing was executed against the real service on this
machine. "Mock" means the adapter was exercised against a fake HTTP server shaped like the provider's documented wire format.

| Provider | Adapter | Mock contract suite | Real chat | Real streaming | Input security | Output security |
|---|---|---|---|---|---|---|
| **Ollama** (`qwen2:0.5b`) | Implemented | PASS | **VERIFIED** | **VERIFIED** | **VERIFIED** | **VERIFIED** |
| Gemini | Implemented | PASS | BLOCKED | BLOCKED | Mock only | Mock only |
| OpenAI | Implemented | PASS | BLOCKED | BLOCKED | Mock only | Mock only |
| Anthropic | Implemented | PASS | BLOCKED | BLOCKED | Mock only | Mock only |

BLOCKED = no API credential is configured on this machine.

One real contact with a cloud provider did happen, and it is recorded precisely: during the Docker verification an
organization stored a **synthetic** OpenAI key, and the gateway (which has internet egress) sent a request with it to
api.openai.com. OpenAI answered 401 and the gateway reported `502 provider_error` with `code: auth`. That verifies the
**authentication-error path and per-organization routing** end to end - it does not verify chat, streaming or any
successful response, which stay BLOCKED.

Since 2026-09-22 an organization can also supply its own key (`PUT /v1/providers/{provider}/credential`, see
`docs/api/organization.md`), so verification can be done with a test organization's key instead of a platform key.

## What "VERIFIED" means for Ollama

Model: `qwen2:0.5b` (qwen2 family, 494.03M parameters, Q4_0, ~352 MB, context 32768). Already installed; nothing was downloaded.

Adapter level (`services/ai-router/tests/providers.test.ts`): `validate()`, `getModels()` against the real API, real chat, real
streaming, and a real error path (a model that is not pulled yields a typed `bad_request`, not a crash or a leak).

Gateway level (`apps/api/tests/e2e/ollamaStream.e2e.test.ts`, 9 tests) — real gateway + real Python security engine + real
token-vault process + real Ollama, with a recording proxy between the router and Ollama so assertions are made on the exact
bytes the model server received:

| Check | Result |
|---|---|
| Real model output streams as SSE and ends with an audited `done` event | PASS |
| The `done` event reports the real model (`qwen2:0.5b`) | PASS — **this failed first and exposed a defect** |
| A reply longer than the hold-back window arrives incrementally | PASS |
| A **secret in the prompt** is blocked and Ollama is never contacted | PASS (proxy recorded zero requests) |
| **PII is tokenized before the real server sees it**; the caller gets the real value back | PASS (proxy bytes contain `[TOK_EMAIL_1]`, never the address) |
| A secret in the model's reply is blocked before leaving the gateway | PASS |
| A secret **split across real NDJSON chunk boundaries** is still detected | PASS — neither half escaped |
| PII the model emits is masked by the output policy | PASS |
| Client disconnect aborts the real upstream request and still audits the partial reply | PASS |
| No prompt, reply or secret text is persisted in any table | PASS |

Output-side blocking is driven deterministically: the proxy rewrites the **real** NDJSON stream to inject content at genuine
chunk boundaries. A 0.5B model cannot be relied on to emit a chosen string on demand, so prompting for one would make the test
flaky and prove less. The transport, chunking and framing are real; the injected content is synthetic and labelled as such.

## Defect found by real-provider testing

**Streamed responses reported a fake model name.** `StreamChunk` carried no model, so `SecureStreamService` fell back to the
literal string `"default"` whenever the caller did not name a model. That value went into the `done` event *and into the
`model` column of the audit record* — a streamed request was audited against a model that does not exist. Every adapter
already resolved the real model at the start of `stream()` but never reported it. Fixed: `StreamChunk` now carries `model`,
all four adapters populate it, and the gateway adopts the first value the provider reports.

This is exactly the class of defect a mock cannot find: the mocks were asserting on the chunks the adapter produced, not on
what the gateway did with them.

## To verify the remaining three

1. Put a real key in `.env` (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
2. The multi-provider e2e already registers any provider whose credential is present, so it will pick them up.
3. Re-run `pnpm --filter @sentinelai/api exec vitest run tests/e2e` and update this matrix with the result.

Costs money and sends data to a third party, so it is opt-in and must never run in CI by default.
