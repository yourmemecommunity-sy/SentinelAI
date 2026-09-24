# Task 2 — Docker: build every image, run the full stack, verify it

Run: **2026-09-26, 07:42–07:49 UTC**, inside WSL2 (Docker Engine 29.1.3, Compose 2.40.3, 12 vCPU / 7 GiB VM), commit `01a65cd`
plus this run's uncommitted changes (`docker-compose.yml` healthcheck for `ollama`, `scripts/development/live-checks.py`).

## Result

| Check | Result |
|---|---|
| All 7 Dockerfiles build | **Yes** — 6 compose images (`docker compose --profile ollama build`, exit 0) + `services/ai-router/Dockerfile` (a library image whose build runs its tests: 58 passed, 3 skipped — the 3 need a live Ollama, which a `docker build` cannot reach; they pass against real Ollama in [01-baseline.md](01-baseline.md)) |
| Full stack up, every service healthy | **Yes** — 10 long-running services `running/healthy`, `migrate` exited 0 |
| Healthchecks | Every long-running service has one. **Added one for `ollama`** (`ollama list`, which only succeeds once its API answers); it had none. `migrate` is a one-shot job |
| Gateway `/ready` | `HTTP 200 {"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":true}` |
| `/v1/security/scan` returns a correct result | Email → `MASK`, `sanitized_text='Please email j***@example.com about the invoice.'`; AWS-shaped key → `BLOCK`, `sanitized_text=None` |
| Dashboard over HTTP | `GET /login` → `HTTP 200`, `<title>Sign in | SentinelAI</title>`, CSP header present |
| Container verification suite (`docker-verify.sh`) | **81 passed, 0 failed, 0 skipped** |

## Build/runtime errors found

None in the images. Two harness bugs in the new live-check script, fixed and re-run (both runs are below):
1. It drew the OCR test image with Pillow **inside** the document-scanner image, which does not ship Pillow (it pipes images to the
   tesseract binary). Now run with the scanner's dev virtualenv, which has it.
2. Its EICAR check accepted *any* block. On the second attempt the scanner was still restarting after `docker-verify.sh`'s
   ClamAV-outage test, and EICAR was blocked with `malware_scan_failed` (a correct fail-closed outcome, but not proof that
   the antivirus recognised the file). The check now requires `reason == malware_detected`, and the final run waits until
   every service is healthy.

## Live checks — final run
```
# Live checks rerun with Pillow available (2026-09-26T08:32:18Z)
PASS gateway /ready
     HTTP 200 {"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":true}
PASS signup
     HTTP 201
PASS create API key
     HTTP 201, key prefix snl_ (value not printed)
PASS scan masks an email
     HTTP 200 decision=MASK entities=['EMAIL'] sanitized_text='Please email j***@example.com about the invoice.'
PASS scan blocks a credential
     HTTP 200 decision=BLOCK entities=['AWS_CREDENTIAL'] sanitized_text=None
PASS dashboard serves /login over HTTP
     HTTP 200, 9700 bytes, <title>Sign in | SentinelAI</title>, CSP header present: True
PASS EICAR upload is blocked (real ClamAV)
     HTTP 200 decision=BLOCK reason=malware_detected failed_closed=False findings=[('malware_detected', 'signature Eicar-Test-Signature')]
PASS screenshot email is OCR'd and masked (real Tesseract)
     HTTP 200 decision=MASK ocr_used=True entities=['EMAIL'] sanitized_text='Customer contact:\nj***@example.com\n'

LIVE CHECKS: ALL PASSED
[exit 0]
```

## Full step log (build, health, first live-check attempt, docker-verify.sh)
```
# STEP 2 - Docker  (2026-09-26T07:42:32Z)
docker 29.1.3, compose 2.40.3+ds1-0ubuntu1, host: 12 vCPU, 7 GiB (WSL2 VM)

## Dockerfiles in the repository
./apps/api/Dockerfile
./apps/dashboard/Dockerfile
./services/ai-router/Dockerfile
./services/document-scanner/Dockerfile
./services/policy-engine/Dockerfile
./services/security-engine/Dockerfile
./services/token-vault/Dockerfile

## Build every compose image
docker compose --profile ollama build -> exit 0
#64 naming to docker.io/sentinel-ai/dashboard:local
#64 naming to docker.io/sentinel-ai/dashboard:local done
#66 naming to docker.io/sentinel-ai/policy-engine:local 0.1s done
#67 naming to docker.io/sentinel-ai/token-vault:local 0.1s done
#54 naming to docker.io/sentinel-ai/api:local 0.1s done
#68 naming to docker.io/sentinel-ai/document-scanner:local 0.1s done
 sentinel-ai/dashboard:local  Built
 sentinel-ai/document-scanner:local  Built
 sentinel-ai/policy-engine:local  Built
 sentinel-ai/token-vault:local  Built
 sentinel-ai/api:local  Built
 sentinel-ai/security-engine:local  Built

## Build the ai-router library image (not a compose service: a library compiled into the gateway; its build runs its tests)
docker build -f services/ai-router/Dockerfile . -> exit 0
#10 5.248 Lockfile is up to date, resolution step is skipped
#10 16.22  ✓ tests/providers.test.ts (51 tests | 3 skipped) 171ms
#10 16.24  Test Files  2 passed (2)
#10 16.24       Tests  58 passed | 3 skipped (61)

## Bring the stack up
docker compose --profile ollama up -d -> exit 0
 Container sentinel-ai-api-1  Healthy
READY: api=running/healthy clamav=running/healthy dashboard=running/healthy document-scanner=running/healthy migrate=exited/ ollama=running/healthy policy-engine=running/healthy postgres=running/healthy redis=running/healthy security-engine=running/healthy token-vault=running/healthy 

## Service health (docker compose ps)
SERVICE            STATE     <no value>   PORTS
api                running   healthy      127.0.0.1:4000->4000/tcp
clamav             running   healthy      3310/tcp, 7357/tcp
dashboard          running   healthy      127.0.0.1:3000->3000/tcp
document-scanner   running   healthy      8003/tcp
ollama             running   healthy      11434/tcp
policy-engine      running   healthy      8002/tcp
postgres           running   healthy      5432/tcp
redis              running   healthy      6379/tcp
security-engine    running   healthy      8001/tcp
token-vault        running   healthy      8004/tcp

## Healthchecks declared per service
  redis             healthcheck
  token-vault       healthcheck
  clamav            healthcheck
  document-scanner  healthcheck
  postgres          healthcheck
  migrate           one-shot job
  security-engine   healthcheck
  api               healthcheck
  dashboard         healthcheck
  policy-engine     healthcheck
  ollama            healthcheck

## Live checks (gateway /ready, /v1/security/scan, dashboard HTTP, file scan)
PASS gateway /ready
     HTTP 200 {"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":true}
PASS signup
     HTTP 201
PASS create API key
     HTTP 201, key prefix snl_ (value not printed)
PASS scan masks an email
     HTTP 200 decision=MASK entities=['EMAIL'] sanitized_text='Please email j***@example.com about the invoice.'
PASS scan blocks a credential
     HTTP 200 decision=BLOCK entities=['AWS_CREDENTIAL'] sanitized_text=None
PASS dashboard serves /login over HTTP
     HTTP 200, 9700 bytes, <title>Sign in | SentinelAI</title>, CSP header present: True
PASS EICAR upload is blocked (real ClamAV)
     HTTP 200 decision=BLOCK reason=malware_detected failed_closed=False findings=[('malware_detected', 'signature Eicar-Test-Signature')]
Traceback (most recent call last):
  File "/s/live-checks.py", line 126, in <module>
    sys.exit(main())
             ^^^^^^
  File "/s/live-checks.py", line 112, in main
    png = png_with_text(["Customer contact:", "jane.doe@example.com"])
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/s/live-checks.py", line 54, in png_with_text
    from PIL import Image, ImageDraw, ImageFont
ModuleNotFoundError: No module named 'PIL'
[live-checks exit 1]

## Full container verification suite (docker-verify.sh)
docker-verify.sh -> exit 0  PASS=81 FAIL=0 SKIP=0
PASS postgres is healthy
PASS redis is healthy
PASS clamav is healthy
PASS token-vault is healthy
PASS security-engine is healthy
PASS document-scanner is healthy
PASS policy-engine is healthy
PASS api is healthy
PASS dashboard is healthy
PASS migrate job exited 0
PASS policy-engine /ready truthfully reports 503 (skeleton by design, nothing depends on it)
PASS api -> security-engine:8001 resolves and answers
PASS api -> token-vault:8004 resolves and answers
PASS api -> document-scanner:8003 resolves and answers
PASS api -> policy-engine:8002 resolves and answers
PASS api resolves postgres and redis by name
PASS document-scanner -> clamav:3310
PASS security-engine -> token-vault
PASS security-engine has NO internet egress (internal backend network)
PASS token-vault has NO internet egress
PASS only the gateway and dashboard are published, on loopback (api=127.0.0.1:4000 dashboard=127.0.0.1:3000)
PASS the plaintext-returning vault is unreachable from the frontend network
PASS api: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 1000
PASS dashboard: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 1000
PASS security-engine: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 10001
PASS token-vault: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 10001
PASS document-scanner: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 10001
PASS policy-engine: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid 10001
PASS Redis refuses unauthenticated clients on the backend network
PASS 8 migrations recorded in schema_migrations
PASS gateway login sentinel_api: NOSUPERUSER, NOBYPASSRLS, member of sentinel_app
PASS the running gateway connects as sentinel_api only
PASS re-running migrations is a no-op (idempotent)
PASS setup: two organizations, API keys, org A TOKENIZE policy  (policy 201)
PASS gateway /ready through service DNS  ({"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":true})
PASS gateway reports every dependency  ({"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":true})
PASS PII is sanitized by the real engine container  (MASK)
PASS a secret is BLOCKED with no text returned
PASS prompt injection is BLOCKED
PASS clean file passes the REAL ClamAV + extraction containers  (ALLOW null)
PASS EICAR is detected by REAL ClamAV and blocked  (malware_detected)
PASS no credentials -> 401
PASS dashboard serves through service DNS with a nonce CSP  (status 200)
PASS dashboard BFF logs in against the gateway container (dashboard -> api)  (status 200)
PASS org B sees none of org A's events (RLS through the containerized gateway)  (A=6 leaked=0)
PASS org B cannot list org A's API keys  (200)
PASS org B fetching an org A event by id gets 404  (404)
PASS invitation created; token returned once  (201)
PASS invitation accepted into org A as DEVELOPER  (201)
PASS invitation token is single-use  (400)
PASS DEVELOPER cannot manage users  (403)
PASS API keys cannot manage users  (403)
PASS disabling a user rejects their existing access token immediately  (disable 200, me 401)
PASS org B's user list contains none of org A's users  (200)
PASS org B cannot modify org A's user (404)  (404)
PASS org A stores its own (synthetic) OpenAI credential  (204 )
PASS provider listing shows only a hint, never the credential  ({"provider":"openai","enabled":true,"source":"organization","organization_credential":{"hint":"QRST","key_
PASS org A's request is routed to org A's own provider instance  (502 {"error":"provider_error","code":"auth","event_id":"4cfda6dc-83bf-4f71-aac5-11be696e1e70"})
PASS org B cannot use org A's credential (blocked unknown_provider)  (403 {"error":"blocked","stage":"input","decision":"BLOCK","failed_closed":true,"reason":"unknown_pro
PASS the stored provider credential is ciphertext only (plaintext absent from the database; sealed with key p1)
PASS invitation tokens are stored only as HMACs
PASS vault in its container: tokenize -> resolve round trip on real Redis, isolated per session
PASS vault keys carry the 3600 s TTL (ttl=3599)
PASS Redis holds no plaintext value
PASS postgres healthy again after restart
PASS audit events survived a Postgres container restart  (now=7 before=7)
PASS persisted events hold no secret or prompt text
PASS the same API key still authenticates after the restart (key hash persisted)
PASS engine stopped -> scan fails CLOSED  (200 engine_unreachable)
PASS engine stopped -> gateway /ready is 503  (503)
PASS document scanner stopped -> upload blocked, no text  (scanner_unreachable)
PASS token vault stopped -> gateway reports token_vault=false  ({"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":false})
PASS ClamAV stopped -> upload blocked (never passed unscanned)  (malware_scan_failed)
PASS Redis stopped -> vault not ready (reported by the gateway)  ({"status":"ready","security_engine":true,"database":true,"document_scanner":true,"token_vault":false})
PASS Postgres stopped -> refused with 503 auth_unavailable (not a misleading 401), nothing returned  (503 auth_unavailable)
PASS Postgres stopped -> fails promptly instead of hanging  (205 ms)
PASS stack fully healthy again after every failure
PASS REAL Ollama streams SSE through the containerized gateway  (200 last=done)
PASS stream audited against the real model name  (qwen2:0.5b)
PASS input tokenized through the containerized vault (org A TOKENIZE policy)  (TOKENIZE)
PASS a secret in a streamed prompt is blocked before any stream opens  (403)
```
