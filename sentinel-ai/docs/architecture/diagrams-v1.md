# SentinelAI v1.0 — architecture, deployment and security flow

## 1. Architecture

```mermaid
flowchart LR
    subgraph clients[Clients]
      APP[Applications]
      JS["@sentinelai/sdk (TS)"]
      PY["sentinelai (Python)"]
      DASH[Dashboard - Next.js BFF]
    end

    subgraph gw[apps/api - Fastify gateway]
      AUTH[Authentication: API key / JWT]
      RBAC[Authorization + tenant resolution]
      VAL[Validation, rate limits, size caps]
      ORCH[Orchestration - fail closed]
      STREAM[SSE streaming: output hold-back + token window]
    end

    subgraph svcs[Services]
      ENG[security-engine - Python<br/>detectors, policy, risk, sanitization]
      VAULT[token-vault - Python<br/>deterministic tokens, AES-256-GCM, TTL]
      DOC[document-scanner - Python<br/>type check, AV, extraction, OCR]
      ROUTER[ai-router - TypeScript<br/>provider adapters]
    end

    subgraph data[State]
      PG[(PostgreSQL<br/>RLS per tenant)]
      REDIS[(Redis<br/>token vault)]
    end

    subgraph models[AI providers]
      OLL[Ollama - local]
      GEM[Gemini]
      OAI[OpenAI]
      ANT[Anthropic]
    end

    APP --> JS & PY --> AUTH
    DASH --> AUTH
    AUTH --> RBAC --> VAL --> ORCH
    ORCH --> ENG
    ENG <--> VAULT
    VAULT --- REDIS
    ORCH --> DOC
    ORCH --> ROUTER --> OLL & GEM & OAI & ANT
    ORCH --> STREAM
    ORCH --> PG
```

## 2. Security flow (one request)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as Gateway
    participant E as Security engine
    participant V as Token vault
    participant M as AI provider
    participant D as Postgres

    C->>G: prompt + API key
    G->>G: authenticate, authorize, validate, rate limit
    G->>E: scan INPUT (org policy, vault session)
    E->>V: tokenize allow-listed entities
    V-->>E: [TOK_EMAIL_1] ...
    E-->>G: decision + sanitized text + risk
    alt BLOCK / QUARANTINE / any failure
        G->>D: audit (metadata only)
        G-->>C: 403 blocked (no content)
    else ALLOW / MASK / REDACT / TOKENIZE
        G->>D: audit INPUT event
        G->>M: sanitized text only
        M-->>G: reply (streamed or whole)
        G->>E: scan OUTPUT (with look-ahead when streaming)
        E-->>G: decision + sanitized reply
        G->>V: resolve tokens for THIS session
        V-->>G: real values
        G->>D: audit OUTPUT event
        G-->>C: safe response
    end
```

Two invariants the diagram encodes: **only sanitized text ever leaves the boundary**, and **the output scan happens before
hydration**, so the scanner never sees the caller's own data and hydrated values are never re-scanned.

## 3. Deployment

```mermaid
flowchart TB
    subgraph verified[Verified on this machine]
      direction LR
      WPG[(PostgreSQL 18.6<br/>WSL2)]
      WRD[(Redis 8.0.5<br/>WSL2)]
      WCL[ClamAV 1.5.3]
      WTS[Tesseract 5.5.0]
      WOL[Ollama qwen2:0.5b]
    end

    subgraph unverified[Written but NEVER executed]
      direction LR
      DC[docker-compose.yml]
      K8S[Kubernetes manifests]
      HELM[Helm chart]
      TF[Terraform]
      CI[GitHub Actions]
    end

    GWP[Gateway] --> WPG & WRD
    ENGP[Security engine] --> WRD
    DOCP[Document scanner] --> WCL & WTS
    RTR[AI router] --> WOL

    classDef blocked fill:#fee,stroke:#c00,stroke-dasharray: 4 3
    class DC,K8S,HELM,TF,CI blocked
```

Red, dashed = **blocked**: Docker is not installed on this machine, so nothing in that box has ever been built or run.
Everything in the upper box was exercised for real; see `docs/release/current-status.md` for exactly what was proven.

## 4. Where state lives

| Data | Store | Retention |
|---|---|---|
| Prompts, replies, uploaded files | **Nowhere** | Never persisted |
| Security events, audit log (types, offsets, decisions, keyed digests) | PostgreSQL | `AUDIT_RETENTION_DAYS` (default 90) |
| Token → value mappings (encrypted) | Redis | Absolute 3600 s from session creation |
| File metadata (sha256, size, type, verdict) | PostgreSQL | Skipped entirely for zero-retention organizations |
| Provider credentials | Operator environment | Not in the database in v1.0 |
