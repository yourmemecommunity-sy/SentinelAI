# Architecture Overview

SentinelAI is a model-agnostic security gateway placed between enterprise applications and AI
providers. Every request and every model response passes through a security pipeline that can
**allow, mask, redact, tokenize, hash, quarantine, or block** content, and records an audit-safe event.

## Security target (stated precisely)

| Target | Meaning |
|---|---|
| 100% enforcement of *defined* prohibited-data policies | Every record of the evaluation suite that a policy prohibits is blocked/sanitized |
| 100% pass on *critical* evaluation cases | Any critical regression fails CI |
| Fail closed | If a safe decision cannot be made, the request is **blocked** and the event audited |

This is an engineering target for defined policies and suites. It is **not** a claim that the system
is universally or mathematically "100% secure" (see [threat-model](../security/threat-model.md) for
known evasion classes).

## Layering (one responsibility each)

```
Frontend -> API Gateway -> AuthN/AuthZ -> Security Pipeline
         -> Security Engine -> Policy -> Risk -> Sanitization
         -> AI Router -> AI Provider -> Output Security -> Audit -> Frontend
```

| Layer | Service | Language | Status |
|---|---|---|---|
| API gateway, API-key auth, RBAC, tenancy, orchestration | `apps/api` | TypeScript | **implemented core** |
| Dashboard | `apps/dashboard` | Next.js | skeleton |
| Detection, policy evaluation, risk, sanitization | `services/security-engine` | Python | **implemented (Phase 1 core)** |
| Policy authoring/storage | `services/policy-engine` | Python | skeleton, fails closed |
| File validation/extraction/OCR/malware scan | `services/document-scanner` | Python | **implemented** (real ClamAV/Tesseract unverified) |
| Provider adapters/routing | `services/ai-router` | TypeScript | **Gemini implemented** |

See [components.md](components.md), [data-flow.md](data-flow.md), [diagrams.md](diagrams.md), and
the [ADRs](adr/).

## Key design decisions

1. **Deterministic detection first** ([ADR-0004](adr/0004-deterministic-detection-first.md)) - no LLM judges attacker-controlled text.
2. **Fail closed everywhere** ([ADR-0002](adr/0002-fail-closed.md)).
3. **Deny-overrides policy with non-overridable floors** ([ADR-0003](adr/0003-policy-semantics.md)).
4. **Detections carry evidence, never values** - location, confidence, severity, keyed digest.
5. **Sanitization is verified** - sanitized text is re-scanned; residual sensitive entities fail closed.
6. **Multi-tenancy from day one** - every tenant-owned row carries `organization_id` ([database](../database/schema.md)).
