#!/usr/bin/env bash
# Verifies the running docker-compose stack end to end: health, service discovery, network isolation, migrations, the
# restricted DB role, functional security, tenant isolation, persistence across restarts, Redis/vault, and fail-closed
# behaviour when each critical dependency is stopped. Run from the repository root inside WSL:
#   bash scripts/development/docker-verify.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a     # secrets for the idempotency check (never printed)

PROJECT=sentinel-ai
NET="${PROJECT}_frontend"
W="${DV_STATE_DIR:-$(mktemp -d)}"      # probe state (tokens of the throwaway test organizations); not root-specific
mkdir -p "$W"
rm -f "$W/state.json" "$W/skipped"
cp scripts/development/docker-verify.mjs "$W/"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
dc() { docker compose "$@"; }
probe() { docker run --rm --network "$NET" -e OLLAMA_MODEL="${OLLAMA_MODEL:-}" -v "$W:/w" node:20-alpine node /w/docker-verify.mjs "$@" || FAIL=$((FAIL + 1)); }
wait_healthy() {
  local svc=$1 t=${2:-180}
  for _ in $(seq 1 "$t"); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q "$svc")" 2>/dev/null)" = "healthy" ] && return 0
    sleep 1
  done
  return 1
}
psql() { dc exec -T postgres psql -U sentinel -d sentinel -tAc "$1"; }

echo "===== 1. containers and health"
# Bounded wait, not a single sample: clamd needs minutes to load its signatures after a (re)start, and during that
# window the scanner and gateway correctly report not-ready. A service that never becomes healthy still fails.
for s in postgres redis clamav token-vault security-engine document-scanner policy-engine api dashboard; do
  if wait_healthy "$s" 420; then pass "$s is healthy"; else fail "$s is $(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q "$s")" 2>/dev/null || echo missing)"; fi
done
# `ps -aq` can list several migrate containers (one per recreate); the newest one is the run that matters.
mig=$(docker inspect -f '{{.State.ExitCode}}' "$(dc ps -aq migrate | tail -1)" 2>/dev/null || echo missing)
[ "$mig" = 0 ] && pass "migrate job exited 0" || fail "migrate job exit=$mig"
pe=$(dc exec -T policy-engine python -c "import urllib.request,urllib.error
try: urllib.request.urlopen('http://localhost:8002/ready',timeout=3); print(200)
except urllib.error.HTTPError as e: print(e.code)" 2>/dev/null)
[ "$pe" = 503 ] && pass "policy-engine /ready truthfully reports 503 (skeleton by design, nothing depends on it)" || fail "policy-engine /ready=$pe"

echo "===== 2. service discovery (Docker DNS, from inside the gateway container)"
for target in security-engine:8001 token-vault:8004 document-scanner:8003 policy-engine:8002; do
  dc exec -T api wget -qO- "http://${target}/health" >/dev/null 2>&1 && pass "api -> ${target} resolves and answers" || fail "api -> ${target}"
done
dc exec -T api sh -c "getent hosts postgres >/dev/null && getent hosts redis >/dev/null" 2>/dev/null && pass "api resolves postgres and redis by name" || fail "name resolution for postgres/redis"
dc exec -T document-scanner python -c "import socket;socket.create_connection(('clamav',3310),5)" 2>/dev/null && pass "document-scanner -> clamav:3310" || fail "document-scanner -> clamav"
dc exec -T security-engine python -c "import urllib.request;urllib.request.urlopen('http://token-vault:8004/health',timeout=4)" 2>/dev/null && pass "security-engine -> token-vault" || fail "security-engine -> token-vault"

echo "===== 3. network isolation"
dc exec -T security-engine python -c "import socket;socket.create_connection(('1.1.1.1',443),4)" >/dev/null 2>&1 && fail "security-engine can reach the internet (backend must be internal)" || pass "security-engine has NO internet egress (internal backend network)"
dc exec -T token-vault python -c "import socket;socket.create_connection(('1.1.1.1',443),4)" >/dev/null 2>&1 && fail "token-vault can reach the internet" || pass "token-vault has NO internet egress"
# Ask Docker what is actually published (PublishedPort != 0). {{.Publishers}} also lists exposed-but-unpublished ports, and
# probing host ports would also hit unrelated host services, so neither is a reliable test.
published=$(docker compose ps --format json | python3 -c '
import json, sys
out = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    rows = json.loads(line)
    for r in (rows if isinstance(rows, list) else [rows]):
        for p in (r.get("Publishers") or []):
            if p.get("PublishedPort"): out.append("%s=%s:%s" % (r["Service"], p.get("URL"), p["PublishedPort"]))
print(" ".join(sorted(out)))')
[ "$published" = "api=127.0.0.1:4000 dashboard=127.0.0.1:3000" ] && pass "only the gateway and dashboard are published, on loopback ($published)" || fail "published: $published"
docker run --rm --network "$NET" node:20-alpine sh -c "wget -qO- -T 3 http://token-vault:8004/health" >/dev/null 2>&1 && fail "the vault is reachable from the frontend network" || pass "the plaintext-returning vault is unreachable from the frontend network"

echo "===== 3b. container hardening"
for svc in api dashboard security-engine token-vault document-scanner policy-engine; do
  cid=$(dc ps -q "$svc")
  h=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}|{{.HostConfig.SecurityOpt}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}' "$cid")
  uid=$(docker exec "$cid" id -u)
  case "$h" in
    "true|[ALL]|[no-new-privileges:true]|"*) [ "$uid" != 0 ] && [ "${h##*|}" != 0 ] && pass "$svc: read-only rootfs, no capabilities, no-new-privileges, memory+pid limits, uid $uid" || fail "$svc: uid=$uid $h" ;;
    *) fail "$svc hardening: $h (uid $uid)" ;;
  esac
done
docker run --rm --network sentinel-ai_backend redis:7-alpine redis-cli -h redis ping 2>&1 | grep -q NOAUTH && pass "Redis refuses unauthenticated clients on the backend network" || fail "Redis accepts unauthenticated clients"

echo "===== 4. migrations and the restricted database role"
n=$(psql "SELECT count(*) FROM schema_migrations")
[ "$n" = 9 ] && pass "9 migrations recorded in schema_migrations" || fail "schema_migrations count=$n"
r=$(psql "SELECT rolsuper::text||','||rolbypassrls::text||','||pg_has_role('sentinel_api','sentinel_app','MEMBER')::text FROM pg_roles WHERE rolname='sentinel_api'")
[ "$r" = "false,false,true" ] && pass "gateway login sentinel_api: NOSUPERUSER, NOBYPASSRLS, member of sentinel_app" || fail "sentinel_api attrs=$r"
# The gateway's pool only holds connections while it is using them, so an idle gateway can show no session at all.
# Make it touch the database (/ready pings it) and sample while that connection is in the pool.
live=""
for _ in 1 2 3 4 5; do
  dc exec -T api wget -qO- http://127.0.0.1:4000/ready >/dev/null 2>&1
  live=$(psql "SELECT DISTINCT usename FROM pg_stat_activity WHERE application_name <> 'psql' AND usename IS NOT NULL AND datname='sentinel'" | tr '\n' ' ')
  echo "$live" | grep -q sentinel_api && break
  sleep 1
done
echo "$live" | grep -q sentinel_api && ! echo "$live" | grep -qw sentinel && pass "the running gateway connects as sentinel_api only" || fail "live DB users: $live"
dc run --rm -T -e DATABASE_URL="postgresql://sentinel:${POSTGRES_PASSWORD}@postgres:5432/sentinel" migrate node db/migrate-pg.mjs 2>/dev/null | grep -q "already up to date" && pass "re-running migrations is a no-op (idempotent)" || fail "migrations not idempotent"

echo "===== 5. functional security through the containers"
probe setup
probe functional

echo "===== 6. tenant isolation through the containerized gateway"
probe isolation

echo "===== 6b. user management + per-organization provider credentials"
probe management
leak=$(psql "SELECT count(*) FROM providers WHERE position(convert_to('sk-synthetic-dv', 'UTF8') IN credentials_encrypted) > 0")
enc=$(psql "SELECT count(*) FROM providers WHERE provider_type = 'openai' AND credentials_encrypted IS NOT NULL AND credential_key_id = 'p1'")
[ "$leak" = 0 ] && [ "$enc" -ge 1 ] && pass "the stored provider credential is ciphertext only (plaintext absent from the database; sealed with key p1)" || fail "provider credential at rest: leak=$leak sealed=$enc"
inv=$(psql "SELECT count(*) FROM invitations WHERE token_hash LIKE 'sni_%'")
[ "$inv" = 0 ] && pass "invitation tokens are stored only as HMACs" || fail "raw invitation tokens in the database: $inv"

echo "===== 7. Redis + token vault (real Redis container, no persistence by design)"
vk=$(dc exec -T redis redis-cli --scan --pattern 'sentinel:vault:v1:*' | wc -l)
echo "INFO vault keys in redis: $vk"
dc exec -T token-vault python - <<'PY' && pass "vault in its container: tokenize -> resolve round trip on real Redis, isolated per session" || fail "vault round trip"
import json, os, urllib.request
T = os.environ["VAULT_TOKEN"]
def call(path, body):
    r = urllib.request.Request("http://localhost:8004" + path, data=json.dumps(body).encode(), method="POST",
                               headers={"content-type": "application/json", "x-internal-token": T})
    return json.loads(urllib.request.urlopen(r, timeout=5).read())
toks = call("/v1/vault/tokenize", {"organization_id": "dv", "session_id": "s1", "items": [{"entity": "EMAIL", "value": "x@example.com"}]})["tokens"]
assert toks == ["[TOK_EMAIL_1]"], toks
assert call("/v1/vault/resolve", {"organization_id": "dv", "session_id": "s1", "tokens": toks})["values"] == {toks[0]: "x@example.com"}
assert call("/v1/vault/resolve", {"organization_id": "dv", "session_id": "other", "tokens": toks})["values"] == {}
PY
ttl=$(dc exec -T redis sh -c "redis-cli --scan --pattern 'sentinel:vault:v1:*' | head -1 | xargs -r redis-cli ttl")
[ -n "$ttl" ] && [ "$ttl" -gt 0 ] && [ "$ttl" -le 3601 ] && pass "vault keys carry the 3600 s TTL (ttl=$ttl)" || fail "vault key ttl=$ttl"
plain=$(dc exec -T redis sh -c "redis-cli --scan --pattern 'sentinel:vault:v1:*' | xargs -r -n1 redis-cli --raw hgetall" | grep -c "x@example.com")
[ "$plain" = 0 ] && pass "Redis holds no plaintext value" || fail "plaintext found in redis ($plain)"

echo "===== 8. persistence across a Postgres restart"
probe snapshot
dc restart postgres >/dev/null
wait_healthy postgres 120 && pass "postgres healthy again after restart" || fail "postgres did not come back"
wait_healthy api 120 || true
probe persisted

echo "===== 9. fail-closed: stop each critical dependency"
for dep in security-engine:engine document-scanner:scanner token-vault:vault; do
  svc=${dep%%:*}; kind=${dep##*:}
  dc stop "$svc" >/dev/null
  sleep 3
  probe expect-blocked "$kind"
  dc start "$svc" >/dev/null
  wait_healthy "$svc" 180 || fail "$svc did not recover"
done
dc stop clamav >/dev/null; sleep 3; probe expect-blocked clamav; dc start clamav >/dev/null; wait_healthy clamav 400 || fail "clamav did not recover"
wait_healthy document-scanner 180 || true
dc stop redis >/dev/null; sleep 5; probe expect-blocked redis; dc start redis >/dev/null; wait_healthy redis 60 || fail "redis did not recover"
wait_healthy token-vault 120 || true
dc stop postgres >/dev/null; sleep 3; probe expect-blocked postgres; dc start postgres >/dev/null; wait_healthy postgres 120 || fail "postgres did not recover"
wait_healthy api 180 && pass "stack fully healthy again after every failure" || fail "api not healthy after recovery"

echo "===== 10. real provider streaming (Ollama profile)"
probe stream

echo
SKIPPED=$( [ -f "$W/skipped" ] && wc -l < "$W/skipped" || echo 0 )
if [ "$FAIL" = 0 ] && [ "$SKIPPED" = 0 ]; then echo "DOCKER VERIFICATION: ALL CHECKS PASSED"
elif [ "$FAIL" = 0 ]; then echo "DOCKER VERIFICATION: ALL EXECUTED CHECKS PASSED, $SKIPPED SKIPPED (not verified):"; sed 's/^/  - /' "$W/skipped"
else echo "DOCKER VERIFICATION: $FAIL CHECK(S) FAILED, $SKIPPED SKIPPED"; fi
exit "$FAIL"
