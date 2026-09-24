# Docker Compose

**Status: VERIFIED.** The full stack builds and runs; `scripts/development/docker-verify.sh` executes 81 checks against
the running stack (health, service discovery, network isolation, migrations, the restricted database role, functional
security, tenant isolation, user/provider management, persistence, fail-closed behaviour for every dependency, and real
streaming through a local model). Last full run: 2026-09-23, all checks passed.

## Bring it up

```bash
bash scripts/development/docker-secrets.sh     # once: writes .env with random secrets (git-ignored)
docker compose build migrate dashboard         # the api image is built by the `migrate` service
docker compose up -d                           # add --profile ollama for a local model
bash scripts/development/docker-up.sh          # waits until api + dashboard are healthy
bash scripts/development/docker-verify.sh      # 81 checks
```

Only two ports are published, both on loopback: the gateway on `127.0.0.1:4000` and the dashboard on `127.0.0.1:3000`.

## Layout

| Service | Image | Notes |
|---|---|---|
| `postgres` | `postgres:18-alpine` | volume `pgdata`; the owner role is used **only** by the migrate job |
| `redis` | `redis:7-alpine` | password-protected, no RDB/AOF (the vault's retention mandate holds on disk too) |
| `clamav` | `clamav/clamav:stable` | real antivirus; first start downloads signatures (minutes), and the scanner fails closed until then |
| `migrate` | builds `sentinel-ai/api:local` | one-shot: migrations (advisory-locked) + provisioning of the restricted login role |
| `token-vault`, `security-engine`, `document-scanner`, `policy-engine` | built here | internal only |
| `api` | `sentinel-ai/api:local` | the only service on both networks: it needs egress to reach cloud providers |
| `dashboard` | built here | talks to the gateway by service name |
| `ollama` | `ollama/ollama` | optional (`--profile ollama`) |

**The `api` image is built by the `migrate` service.** `docker compose build api` is a silent no-op, because `api` only
references the image — build `migrate` (this bit me once; the stack ran old code while every check reported healthy).

## Hardening applied to the running containers

* Every image built from this repository: `read_only` root filesystem, `cap_drop: [ALL]`, `no-new-privileges`,
  tmpfs `/tmp`, pid and memory limits, non-root user (verified with `docker inspect`, not just declared).
* `backend` is an internal network: the engine, vault, scanner and databases have **no route to the internet**.
* Redis requires a password, so no other container on the backend network can read or flush the vault's entries.
* Image scanning (Trivy, `--ignore-unfixed`): **0 fixable HIGH/CRITICAL in all six images**. The Node images carry no
  package manager at all (npm was removed: it was the source of every fixable finding). The Debian-based Python images
  still carry base-image CVEs with no upstream fix — see `docs/release/v1.0-release-report.md`.

## Where the data goes

Uploads are never persisted (memory only). The vault keeps ciphertext in Redis with an absolute TTL. `pgdata` is the only
durable volume; back it up like any database.
