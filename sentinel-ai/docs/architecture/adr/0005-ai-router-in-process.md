# ADR-0005: `ai-router` is an in-process library first

**Status:** accepted

**Context.** The spec lists `services/ai-router` as a service. A network hop between gateway and router adds latency and a new
fail-closed boundary, but no security benefit while both are trusted first-party code.

**Decision.** `@sentinelai/ai-router` is a workspace library imported by the gateway (`AiRouter`, `GeminiProvider`, ...). The
package boundary and the `AIProvider` interface keep it extractable into its own service later without touching the core.

**Security-relevant rules encoded in the router**
- Unknown provider => `UnknownProviderError` => gateway blocks and audits (never a 404/500).
- **No automatic cross-provider fallback.** Re-routing sanitized content to a provider the policy did not approve would bypass policy.
- Provider errors never contain request bodies or credentials; API keys travel in headers, never URLs.
- Model ids are allow-listed before being placed in a URL.
- Base URLs must be http(s) without embedded credentials, and are **operator configuration only**: a request must never be able to choose one (SSRF via `OllamaProvider`/OpenAI-compatible endpoints).
- Provider error text (which may echo prompts or provider diagnostics) is never propagated; only status-derived codes are.
