# security-engine

Python service that detects, evaluates, sanitizes and scores content. Stateless; the gateway passes the policy inline.

```bash
pip install -e ".[dev]"
python -m pytest -q
uvicorn app.main:app --port 8001
```

- `POST /v1/scan` - contract in `docs/api/openapi.yaml`
- `GET /health` (liveness), `GET /ready` (readiness incl. canary self-test)

Environment: `SENTINEL_ENV`, `SECURITY_ENGINE_TOKEN` (required in production), `SECURITY_MAX_INPUT_CHARS`, `SECURITY_TIME_BUDGET_MS`, `SENTINEL_DIGEST_KEY`.

Extending: subclass `app.detectors.base.Detector` and `DetectorRegistry.register(...)`; add cases to the datasets generator and run the evaluation gate.
Every failure to reach a safe decision returns `BLOCK` with `failed_closed=true` (see `docs/architecture/adr/0002-fail-closed.md`).

Known limitations: no NER/ML layer yet; rule-based injection detection can miss paraphrases. See `docs/security/threat-model.md`.
