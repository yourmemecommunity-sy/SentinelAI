# Task 6 — Real AI provider

Run: **2026-09-26** (baseline 10:55–11:48 IST; live stack 08:35 UTC).

## Cloud providers (Gemini / OpenAI / Anthropic): BLOCKED — no API key

Presence was checked by name only (no value is ever printed):

```
windows env GEMINI_API_KEY: absent
windows env OPENAI_API_KEY: absent
windows env ANTHROPIC_API_KEY: absent
no windows .env
wsl deployment .env GEMINI_API_KEY: empty
wsl deployment .env OPENAI_API_KEY: empty
wsl deployment .env ANTHROPIC_API_KEY: empty
```

No credential exists, so the SDK → gateway → engine → cloud-provider path was **not run**. The three cloud adapters remain
**mock-verified only** (contract and wire-format tests against stand-in HTTP servers). To unblock: put a real key in
`sentinel-ai/.env` (for example `GEMINI_API_KEY=…`), restart the stack, and run
`cd apps/api && npx vitest run tests/e2e/multiProvider.e2e.test.ts` plus the SDK e2e. Both already assert "masked before
the provider receives it" and "a blocked secret never reaches the provider", using a recording proxy.

## Ollama (real local model, `qwen2:0.5b`): VERIFIED

**14 tests hit the real Ollama server**, all passed in the baseline run ([01-baseline.md](01-baseline.md)). The ones that
answer the task's two questions:

| Proof | Test |
|---|---|
| **Masking happened before the provider received the text** | `packages/sdk/javascript/tests/e2e.test.ts` › *REAL local model via Ollama (SDK -> gateway -> real engine -> real Ollama) › PII is masked before the REAL Ollama server receives it; a secret never reaches it at all*. A recording pass-through proxy sits between the gateway and Ollama, and the test asserts on the exact bytes Ollama received: the masked `j***@example.com` is present, `jane.doe` is absent, and for the secret prompt the proxy saw **zero** requests |
| **A blocked secret never reached the provider** | Same test (the proxy recorded no request for the secret-bearing prompt), and `apps/api/tests/e2e/ollamaStream.e2e.test.ts` › *a SECRET in the prompt is blocked and the REAL Ollama server is never contacted* |
| Tokenized before the real server sees it, hydrated for the caller | `ollamaStream.e2e` › *PII is tokenized before the REAL server sees it, and the caller gets the real value back* |
| Output side | `ollamaStream.e2e` › *a secret the REAL model emits is blocked before it leaves the gateway*; *a secret SPLIT across real stream chunks is still detected*; *PII the REAL model emits is masked* |

Real-Ollama tests in the baseline (all passed):
```
PASSED SDKs against the real gateway + real security engine REAL local model via Ollama (SDK -> gateway -> real engine -> real Ollama) a request is scanned, sent to the real model, the reply is scanned, and both stages are audited
PASSED SDKs against the real gateway + real security engine REAL local model via Ollama (SDK -> gateway -> real engine -> real Ollama) PII is masked before the REAL Ollama server receives it; a secret never reaches it at all
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) a clean prompt streams REAL model output and ends with an audited done event
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) a reply longer than the hold-back window is served incrementally, not in one lump
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) a SECRET in the prompt is blocked and the REAL Ollama server is never contacted
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) PII is tokenized before the REAL server sees it, and the caller gets the real value back
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) a secret the REAL model emits is blocked before it leaves the gateway (injected at genuine NDJSON boundaries)
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) a secret SPLIT across real stream chunks is still detected (this is what the look-ahead is for)
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) PII the REAL model emits is masked by the OUTPUT policy rather than passed through
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) disconnecting mid-stream aborts the REAL upstream request and still audits what was scanned
PASSED REAL Ollama streaming through the gateway (model: qwen2:0.5b) no prompt, reply or secret text is persisted anywhere in the database
PASSED REAL local Ollama server validate() and getModels() work against the real API
PASSED REAL local Ollama server a model that is not pulled yields a typed bad_request (real server error path), not a crash or leak
PASSED REAL local Ollama server real chat and streaming with the first installed model
```

## Both SDKs through the running Docker stack (containerised gateway + engine + vault) to real Ollama

```
# SDK -> containerised gateway -> real engine -> real Ollama (qwen2:0.5b), 2026-09-26T08:35:39Z
## JavaScript SDK
[exit 0]
PASS JS SDK streams from the real gateway and a real model  (1 deltas)
PASS the summary reports the real model and both security verdicts  (model=qwen2:0.5b input=TOKENIZE output=ALLOW)
PASS PII in the prompt was TOKENIZED before the model saw it  (TOKENIZE)
PASS hydration was applied through the real token vault  (applied)
PASS a secret in a streamed prompt raises SentinelBlockedError (input stage, nothing streamed)  (SentinelBlockedError stage=input)
PASS breaking out early is not reported as a complete reply  (SentinelUnavailableError)
## Python SDK
PASS Python SDK streams from the real gateway and a real model  (1 deltas)
PASS the summary reports the real model and both security verdicts  (model=qwen2:0.5b)
PASS PII in the prompt was TOKENIZED before the model saw it  (TOKENIZE)
PASS a secret in a streamed prompt raises SentinelBlockedError (input stage)  (SentinelBlockedError)
[exit 0]
```
