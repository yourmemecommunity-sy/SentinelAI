# Local Development

Prerequisites: Python >= 3.11, Node >= 20, pnpm 9 (install: `npm i -g pnpm`), optionally Docker.

## What runs today
```bash
# security engine
cd services/security-engine
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q                                # 110+ tests
uvicorn app.main:app --port 8001                   # http://localhost:8001/ready

# evaluation gate (from repo root, using the engine environment)
python scripts/security/run_evaluation.py
python -m pytest tests/security tests/regression

# repo structure gate
node scripts/development/validate-structure.mjs
node --test tests/unit/validate-structure.test.mjs
```
Regenerate datasets (deterministic): `python scripts/dataset/generate_synthetic_datasets.py`.

## TypeScript gateway
```bash
npx pnpm@9 install
pnpm build                     # typecheck + build shared-types, ai-router, api
pnpm test                      # ai-router + gateway: unit, tenant isolation (PGlite), migrations, e2e vs the real engine
```
The e2e test spawns the Python engine (uses `services/security-engine/.venv`, or set `SENTINEL_E2E_PYTHON`; that environment needs `uvicorn`).
To run the gateway for real you need PostgreSQL: `DATABASE_URL=<owner url> pnpm db:migrate`, then set the env vars from `.env.example` and run `node apps/api/dist/server.js`.
Sign up through the dashboard (or `POST /v1/auth/signup`), then create API keys on the **API keys** page (or `POST /v1/api-keys`).

## Whole product, one command (no Docker, no database server)
```bash
npx pnpm@9 install && pnpm build          # once
node scripts/development/dev-stack.mjs --prod     # engine :8001, gateway :4000 (in-memory Postgres), dashboard :3000
```
Open http://localhost:3000, create an organization on the registration page, then use the scan playground. Data is in memory and lost on exit;
dev secrets are baked into `apps/api/dev/devServer.ts` (which refuses to run with `NODE_ENV=production`). A provider named `echo` is registered
for demos (add `GEMINI_API_KEY` to also register Gemini).

The dev server prints `SENTINEL_DEV_API_KEY=snl_...` on start; with it (and `SENTINEL_BASE_URL=http://localhost:4000`) the SDKs can be tried against the `echo` provider.

## Not runnable yet
SDK publishing, policy-engine service, real ClamAV/Tesseract (the dev stack uses the EICAR-only baseline scanner and blocks images without OCR), dashboard pages that need unbuilt APIs.
