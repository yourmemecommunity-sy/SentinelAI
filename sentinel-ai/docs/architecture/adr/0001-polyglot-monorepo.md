# ADR-0001: Polyglot monorepo at `sentinel-ai/`

**Status:** accepted

**Context.** The spec fixes TypeScript for the gateway/router/dashboard and Python for detection/NLP/ML.
The workspace (`googleAi/`) was empty apart from an empty linked folder `Sentinel/`.

**Decision.** One monorepo rooted at `googleAi/sentinel-ai/`, pnpm workspaces for TS packages, per-service
`pyproject.toml` for Python. Services communicate only through documented HTTP contracts (OpenAPI; snake_case JSON
on the wire, mirrored in `packages/shared-types`). `pnpm-lock.yaml` is permitted at the root as a generated lockfile.

**Consequences.** Clear module boundaries and one CI; two toolchains to maintain. The structure validator enforces layout.
