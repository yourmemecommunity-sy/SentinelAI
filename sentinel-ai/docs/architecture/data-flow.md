# Data Flow

## Request lifecycle

```mermaid
flowchart TD
    C[Client / SDK] --> G[API Gateway]
    G --> AN[Authentication]
    AN --> AZ[Authorization + tenant resolution]
    AZ --> V[Request validation]
    V --> SE[Security Engine]
    subgraph SE_[Security Engine - implemented]
      SE --> D1[PII / Financial detectors]
      D1 --> D2[Secret + credential detectors + entropy]
      D2 --> D3[Prompt-injection detector]
      D3 --> D4[Confidential-data detector]
      D4 --> P[Policy evaluation]
      P --> S[Sanitization]
      S --> VR[Re-scan verification]
      VR --> R[Risk engine]
    end
    R -->|BLOCK / QUARANTINE| A1[Audit event + error to client]
    R -->|ALLOW / MASK / REDACT / TOKENIZE / HASH| RT[AI Router]
    RT --> M[Gemini / Claude / OpenAI / Ollama]
    M --> OS[Output scan - same engine, direction=OUTPUT]
    OS --> OP[Output policy]
    OP -->|BLOCK| A2[Audit + safe refusal]
    OP -->|ALLOW / SANITIZE| DT[De-tokenize if policy allows]
    DT --> A3[Audit event]
    A3 --> C
```

## File upload lifecycle

```mermaid
flowchart TD
    U[Client / SDK: raw bytes] --> G[Gateway: auth, scan:use, rate limit, size cap]
    G --> DS[document-scanner]
    subgraph DS_[document-scanner - memory only]
      DS --> T[Magic-byte type check vs extension]
      T --> M[Malware scan - before any parser]
      M --> X[Isolated child process: parse / OCR, hard timeout]
    end
    X -->|BLOCK: macro, active content, malware, bomb, mismatch, error| AB[Audit + BLOCK, no text]
    X -->|text + findings| V[Gateway verifies sha256 / size]
    V --> E[Security Engine + org policy on extracted text]
    E --> D[Decision; hidden-text findings raise the risk floor]
    D --> AU[Audit file_scan event + metadata-only file record]
```

Every failure (scanner unreachable, timeout, parser error, OCR/AV unavailable, integrity mismatch) is a `BLOCK` with `failed_closed=true` and empty text.

## Fail-closed edges

Any of these produce `decision=BLOCK`, `failed_closed=true`, a machine-readable reason, and an audit event:

| Condition | Reason code |
|---|---|
| Input exceeds `max_input_chars` | `input_too_large` |
| A detector raises | `detector_error:<name>:<ExceptionType>` |
| Time budget exceeded between stages | `timeout` |
| No detectors registered | `no_detectors_registered` |
| Policy evaluation raises | `policy_error:<ExceptionType>` |
| Sanitized text still contains a sanitized entity type | `sanitization_verification_failed` |
| Any other exception | `internal_error:<ExceptionType>` |
| Gateway cannot reach/parse the engine (`engine_unreachable`, `engine_timeout`, `engine_http_<n>`, `engine_invalid_response`, `engine_invariant_violation`) | gateway |
| Unknown provider / policy store unreachable / audit store unwritable | `unknown_provider` / `policy_unavailable` / `audit_unavailable` (503) |
| Document scanner unreachable, times out, or replies inconsistently / with a mismatching hash | `scanner_*` (BLOCK) |
| Scanner-side: bad type, macro, active content, malware, bomb, parser crash/timeout, missing AV/OCR | reason from the scanner (BLOCK, no text) |

## What is persisted

| Data | Stored? |
|---|---|
| Prompt / response text | **No** (zero-retention default; see [privacy](../security/privacy.md)) |
| Entity types, offsets, risk, decision, policy id, detector version | Yes (audit) |
| Keyed digest of matched value | Yes, optional, for correlation only |
| Token-vault mappings | Request lifetime only, in memory / TTL cache |
| Uploaded files | **No** (memory only, never written to disk or object storage) |
| File metadata (sha256, size, detected type, verdict; never the name) | Yes, unless the org is zero-retention |
