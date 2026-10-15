# @sentinelai/devicepulse-contracts

Versioned request and response contracts for the DevicePulse diagnostics API, as Zod schemas plus the catalog of every
enumerated value (diagnostic types, metrics with units and bounds, local finding codes, approved action ids, limitation,
disclaimer and error codes).

- `src/v1/catalog.ts` — the catalog and limits for schema version 1.0
- `src/v1/request.ts` — request schemas and `validateExplainRequest` / `validateFeedbackRequest` (strict schema, consent,
  units, bounds, timestamps, evidence references; error messages never echo client values)
- `src/v1/response.ts` — response, error, health and capabilities schemas
- `examples/v1/*.json` — example payloads, validated by `tests/v1.test.ts`; safe to copy into client tests

Field-level documentation: `docs/devicepulse/api-contracts.md`. Versioning: a breaking change gets a new `src/v2`
directory served alongside v1; additive changes bump the minor schema version.

```bash
pnpm --filter @sentinelai/devicepulse-contracts test
```
