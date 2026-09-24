# Streaming and reversible tokenization

## What happens to a request
```
client -> gateway: auth, RBAC, size, per-caller stream limit
       -> input screening (identical to /v1/ai/chat): every message scanned with the org policy; TOKENIZE actions write to the
          token vault (engine -> vault) under a session derived from the caller
       -> provider stream (router adapter, AbortSignal wired to the client socket)
       -> OutputScreen: text is scanned WITH a look-ahead before it is released; masked/redacted by the OUTPUT policy
       -> TokenWindow: tokens split across chunks are held (<= 44 chars) and hydrated from the vault
       -> SSE frames to the client
```
Order matters: **scan, then hydrate**. The output scanner only ever sees tokens, never the caller's own data, and hydrated values are
never rescanned (rescanning would block or mask exactly what the policy chose to tokenize for that caller). A test asserts the OUTPUT
scan never contains the plaintext.

## Sessions
* `session_id` (optional, `/v1/ai/chat` and `/v1/ai/stream`) names a vault session so tokens stay stable across turns.
* The vault session is `SHA-256(org, principal, session_id)`: two callers sending the same `session_id` get unrelated sessions, and a caller
  cannot name (or guess) someone else's. Without `session_id` the session is random and deleted when the request ends.
* Mappings live for an absolute 3600 s from creation (configurable, max 24 h). Reads and writes never extend it.
* Only allow-listed entity types are tokenizable. Credentials, secrets, cards and threat entities are refused by the vault; the engine then
  redacts them (and the risk engine blocks them anyway).

## Wire format (`POST /v1/ai/stream`, `text/event-stream`)
```
event: delta   data: {"text":"..."}
event: done    data: {"provider","model","hydration":"applied|degraded|off","security":{"input":{decision,risk_level,event_id},"output":{...}}}
event: error   data: {"error":"blocked","stage":"output","decision","failed_closed","reason","event_id"}
               | {"error":"provider_error","code","event_id"} | {"error":"audit_unavailable"|"idle_timeout"|"max_duration"}
```
Failures before the first byte (validation, auth, blocked input, audit outage, 429 too many streams) are ordinary JSON responses with the same
codes as `/v1/ai/chat`. After the first byte the HTTP status is already 200, so **a client must treat anything other than a final `done` event as
a failure**. `mode: "buffered"` releases nothing until the whole reply has been scanned once. Each `data:` is one JSON line, so model text cannot
forge frames.

## Failure behaviour
| Situation | Result |
|---|---|
| Vault down while a prompt needs tokens | Engine fails closed: request blocked (`vault_unavailable`), provider never called |
| Vault down while hydrating a reply | Tokens stay in the text (no plaintext released), `done.hydration = "degraded"` |
| Secret in the model reply | Stream ends with `error/blocked`; text already released was scanned; the secret and its held-back look-ahead were not sent |
| Client disconnects | Upstream provider request aborted, partial output audited, ephemeral session deleted, concurrency slot freed |
| Provider stalls / runs too long | `idle_timeout` / `max_duration`, upstream aborted |
| Output event cannot be recorded | `error/audit_unavailable` instead of `done` |

## Known limitations
* **Look-ahead is finite.** A sensitive value longer than `STREAM_HOLDBACK_CHARS` (default 256) that only becomes detectable at its very end
  could have had its beginning released. Use `mode: "buffered"` (or a larger hold-back) for content where that matters. A control test shows why
  the hold-back exists: with none, a secret split across chunks is never seen whole.
* **Released text cannot be recalled.** A mid-stream block stops the stream; earlier (scanned) text is already with the client.
* An output audit failure after text was released can only be reported, not undone.
* Never run against a real Redis server, real Anthropic/Gemini SSE, or a real browser `EventSource` (a `fetch` reader was used). The SDKs do not expose streaming yet.
* The vault trusts the tenant and session it is given: only the gateway and engine may call it (internal token; mTLS and network policy are still to do).
