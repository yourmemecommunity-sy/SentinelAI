# JavaScript / TypeScript SDK (`@sentinelai/sdk`)

**Status: implemented** (`packages/sdk/javascript`; 25 unit tests with a real HTTP server + cross-language e2e against the real gateway and engine). Not yet published to npm. Node >= 18, ESM, zero runtime dependencies.

```ts
import { SentinelAI, SentinelBlockedError } from "@sentinelai/sdk";

const client = new SentinelAI({ apiKey: process.env.SENTINEL_API_KEY, baseUrl: "https://gateway.example.com" });

try {
  const res = await client.secure({ provider: "gemini", prompt: userPrompt });
  console.log(res.content);            // already scanned on the way in AND out
} catch (e) {
  if (e instanceof SentinelBlockedError) console.warn(e.stage, e.decision, e.eventId); // never contains content
  else throw e;
}
```

| Method | Behaviour |
|---|---|
| `secure({ provider, prompt, system?, model?, ... })` / `chat({ provider, messages, ... })` | Full pipeline (`POST /v1/ai/chat`). Returns `{ content, provider, model, security }` or **throws** |
| `scan({ text, direction? })` | Decision, evidence and `sanitizedText` without calling a model. A blocked result is *returned* (`blocked: true`, `sanitizedText: null`) |
| `check({ text })` | `allowed` is true only for an unmodified `ALLOW` |
| `scanFile({ data, filename?, ... })` | Uploads raw bytes to `POST /v1/files/scan` (only the extension of `filename` is sent). Returns `{ decision, blocked, reason, file, findings, detections, sanitizedText, ... }`. A blocked file is *returned* (`blocked: true`, `sanitizedText: null`), so **check `blocked` before using the text** |

Configuration also comes from `SENTINEL_API_KEY` and `SENTINEL_BASE_URL`. Every call accepts `application`, `team`, `environment` (used for policy scoping) and an `AbortSignal`.

## Errors (all extend `SentinelError`; none ever contain the key, prompt or response)
`SentinelBlockedError` (403 blocked: `stage`, `decision`, `failedClosed`, `reason`, `eventId`), `SentinelAuthenticationError` (401), `SentinelPermissionError` (403),
`SentinelValidationError` (413/422, with `issues`), `SentinelRateLimitError` (429, `retryAfterSeconds`), `SentinelProviderError` (502),
`SentinelUnavailableError` (network, timeout, 5xx, unusable response), `SentinelConfigError` (bad configuration, before any request).

## Fail-closed and credential-safety guarantees
- Content is returned **only** for a 200 with a well-formed body. Network errors, timeouts, malformed or self-contradictory replies (e.g. a blocked decision that still carries text) throw.
- `baseUrl` must be `https://` unless it is localhost (`allowInsecureHttp` opts out); credentials in the URL are refused.
- Redirects are never followed, so the key cannot be forwarded to another host.
- The key is validated locally (`snl_...` shape) without being echoed, sent only as `Authorization: Bearer`, and redacted from `console.log` / `util.inspect` / `JSON.stringify` of the client.
- **No automatic retries**: a chat request is not idempotent (provider cost, audit trail), so retry policy is left to the caller (`SentinelRateLimitError.retryAfterSeconds` helps).

## Not implemented
Streaming uploads (the whole file is held in memory), policy/event management calls (API keys are created in the dashboard or via `/v1/api-keys` with a user session), Deno/browser packaging (a browser must never hold an API key; use the dashboard BFF pattern instead).
