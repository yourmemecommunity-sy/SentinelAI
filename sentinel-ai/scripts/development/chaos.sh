#!/usr/bin/env bash
# Chaos test of the running docker-compose stack: injects faults WHILE continuous load runs, then checks the fail-closed
# invariant over every single response (see chaos-load.mjs) and that the stack recovers on its own.
#
#   bash scripts/development/chaos.sh            (from the repository root, inside WSL, stack up)
#
# Faults (each while load is running):
#   1. security engine FROZEN (docker pause: accepts connections, never answers)  -> a hang, not a crash
#   2. token vault SIGKILLed                                                        -> abrupt death
#   3. security engine cut off the network (docker network disconnect)             -> partition
#   4. Postgres restarted                                                           -> audit/auth store outage
#   5. gateway SIGKILLed and restarted by its restart policy                        -> in-flight requests lost
set -uo pipefail
cd "$(dirname "$0")/../.."
dc() { docker compose "$@"; }
NET=sentinel-ai_frontend
W="${CHAOS_DIR:-$(mktemp -d)}"
cp scripts/development/chaos-load.mjs "$W/"
log() { echo "[$(date +%T)] $*"; }

cat > "$W/mkkey.mjs" <<'JS'
// Creates a throwaway organization and prints a DEVELOPER API key; exits non-zero (with the reason) on any failure.
const API = "http://api:4000"; const slug = `chaos-${Date.now().toString(36)}`;
const s = await fetch(`${API}/v1/auth/signup`, { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ organization_name: slug, email: `${slug}@example.com`, password: "Str0ng-Chaos-Passw0rd!" }) });
const sj = await s.json(); if (s.status !== 201) { console.error(`signup ${s.status} ${sj.error}`); process.exit(1); }
const k = await fetch(`${API}/v1/api-keys`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${sj.access_token}` },
  body: JSON.stringify({ name: "chaos", role: "DEVELOPER" }) });
const kj = await k.json(); if (k.status !== 201) { console.error(`api key ${k.status} ${kj.error}`); process.exit(1); }
const pol = await fetch(`${API}/v1/policies`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${sj.access_token}` },
  body: JSON.stringify({ policy_id: "chaos-tokenize", rules: [{ entity: "EMAIL", action: "TOKENIZE" }] }) });
if (pol.status !== 201) { console.error(`policy ${pol.status}`); process.exit(1); }
const t = await fetch(`${API}/v1/security/scan`, { method: "POST", headers: { "content-type": "application/json", "x-sentinel-api-key": kj.key }, body: JSON.stringify({ text: "hello" }) });
if (t.status !== 200) { console.error(`key does not work: scan ${t.status}`); process.exit(1); }
console.log(kj.key);
JS
KEY=$(docker run --rm --network "$NET" -v "$W:/w" node:20-alpine node /w/mkkey.mjs) || { echo "could not create a working test key"; exit 2; }
case "$KEY" in snl_*) ;; *) echo "unexpected key output"; exit 2 ;; esac

DURATION=200
log "load starts ($DURATION s, 6 workers paced to ~8 req/s, under the production rate limit)"
set -a; . ./.env; set +a
CHAT=""; [ -n "${OLLAMA_MODEL:-}" ] && [ -n "$(dc ps -q ollama 2>/dev/null)" ] && CHAT=ollama
[ -n "$CHAT" ] && log "a chat worker exercises the vault through the real $CHAT model" || log "SKIP chat worker: Ollama not running (vault outage NOT exercised)"
docker run --rm --network "$NET" -e CHAT_PROVIDER="$CHAT" -v "$W:/w" node:20-alpine node /w/chaos-load.mjs "$DURATION" "$KEY" /w/results.jsonl > "$W/load.log" 2>&1 &
LOAD=$!
sleep 15

log "FAULT 1: freeze the security engine for 20s";   dc pause security-engine >/dev/null;  sleep 20; dc unpause security-engine >/dev/null; log "engine resumed"
sleep 15
# The outage window is stamped from when `kill` has RETURNED (the vault is certainly dead; `docker compose` itself can
# take over a second to start under load) to just before `start` is issued.
log "FAULT 2: SIGKILL the token vault";               dc kill -s KILL token-vault >/dev/null; V0=$(( $(date +%s%N) / 1000000 )); sleep 15; V1=$(( $(date +%s%N) / 1000000 )); dc start token-vault >/dev/null; log "vault restarted"
echo "$V0 $V1" > "$W/vault_window"
sleep 10
log "FAULT 3: partition the engine from the backend network for 20s"
docker network disconnect sentinel-ai_backend "$(dc ps -q security-engine)"; sleep 20
docker network connect --alias security-engine sentinel-ai_backend "$(dc ps -q security-engine)"; log "engine reconnected"
sleep 15
log "FAULT 4: restart Postgres";                      dc restart postgres >/dev/null; log "postgres back"
sleep 15
log "FAULT 5: SIGKILL the gateway (restart policy brings it back)"; dc kill -s KILL api >/dev/null; dc start api >/dev/null; log "gateway started"

wait "$LOAD"
cat "$W/load.log"

echo "===== invariant check over every response"
python3 - "$W/results.jsonl" "$W/vault_window" <<'PY'
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
v0, v1 = (int(x) for x in open(sys.argv[2]).read().split())
by = collections.Counter(r["cls"] for r in rows)
leaks = [r for r in rows if r["cls"] == "LEAK"]
errs = [r for r in rows if r["cls"] == "server_error"]
hangs = [r for r in rows if r["cls"] == "timeout"]
conn = [r for r in rows if r["cls"] == "conn_error"]
slow = [r for r in rows if r["ms"] > 10_000]
print(f"requests: {len(rows)}  classes: {dict(by)}")
print(f"reasons for refusals: {dict(collections.Counter(r['reason'] for r in rows if r['cls'] not in ('ok','blocked')))}")
print(f"max latency: {max(r['ms'] for r in rows)} ms; >10s: {len(slow)}")
ok = True
if leaks: ok = False; print("FAIL secret-bearing requests that were let through:", leaks[:5])
else: print(f"PASS no secret-bearing request was let through and no raw email escaped tokenization ({sum(1 for r in rows if r['kind'] != 'scan-clean')} such requests, across all faults)")
vault = collections.Counter(r["reason"] for r in rows if r["kind"] == "scan-tokenize" and r["cls"] != "tokenized")
print(f"INFO tokenizing requests not served normally, by reason: {dict(vault)}")
if errs: ok = False; print("FAIL non-503 5xx responses:", collections.Counter((r['status'], r['reason']) for r in errs))
else: print("PASS no unexpected 5xx: every outage surfaced as a refusal (403 fail-closed / 503)")
if hangs: ok = False; print(f"FAIL {len(hangs)} requests HUNG (no answer within 15s), at t={sorted(set(int(r['t']) for r in hangs))[:10]}")
else: print("PASS no request hung: every fault was answered within the client timeout")
processed = sum(1 for r in rows if r["cls"] not in ("refused_429",))
print(f"INFO {len(conn)} connection errors (gateway being killed/restarted) at t={sorted(set(int(r['t']) for r in conn))[:10]}")
if processed < len(rows) * 0.9: ok = False; print(f"FAIL only {processed}/{len(rows)} requests reached the pipeline (rate limited?) - the run proves little")
chats = [r for r in rows if r["kind"] == "chat-tokenize"]
if chats:
    # A chat counts as "during the outage" only if its WHOLE lifetime lies inside the window: one that started before
    # the kill may already hold its tokens, and one still running at the restart may reach the restarted vault. Those
    # boundary chats are listed, not judged.
    down = [r for r in chats if v0 <= r["at"] and r["at"] + r["ms"] <= v1]
    served = [r for r in down if r["status"] == 200]
    edge = [r for r in chats if r not in down and r["at"] <= v1 and r["at"] + r["ms"] >= v0]
    print(f"INFO chats with a vault session: {len(chats)} ({dict(collections.Counter(r['cls'] for r in chats))}); during the vault outage: {len(down)} -> {dict(collections.Counter((r['status'], r['reason']) for r in down))}")
    for r in edge + served:
        print(f"INFO {'SERVED-IN-OUTAGE' if r in served else 'boundary'} chat: started {r['at'] - v0:+d} ms from the kill, took {r['ms']} ms, window {v1 - v0} ms -> {r['status']} {r['reason']}")
    if not down: ok = False; print("FAIL no chat was attempted while the vault was down - the outage was not exercised")
    elif served: ok = False; print(f"FAIL {len(served)} chats that need the vault were SERVED while it was down")
    else: print(f"PASS every chat that needed the vault failed closed while it was down ({len(down)} of {len(down)})")
    if not any(r["status"] == 200 and r["at"] > v1 + 5000 for r in chats): ok = False; print("FAIL chats did not recover after the vault came back")
    else: print("PASS chats recovered after the vault came back")
tail = [r for r in rows if r["t"] > max(x["t"] for x in rows) - 8]
print(f"last 8s: {dict(collections.Counter(r['cls'] for r in tail))}")
sys.exit(0 if ok else 1)
PY
INV=$?
echo "===== recovery"
bash scripts/development/docker-up.sh | tail -1
[ "$INV" = 0 ] && echo "CHAOS: INVARIANTS HELD" || echo "CHAOS: INVARIANT VIOLATED"
exit "$INV"
