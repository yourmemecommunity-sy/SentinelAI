#!/usr/bin/env bash
# Mid-stream API-key revocation test against the running compose stack (WSL/Linux, from the repository root):
#
#   bash scripts/security/run-stream-revocation-test.sh <label> [out dir, default /root/revocation-out]
#   TRIALS=24 PARALLEL=4 BG_STREAMS=16 REVOKE_AFTER_MS=1500 MOCK_STREAM_TOKENS=400 MOCK_TOKEN_MS=25 bash ...   (defaults)
#
# What it changes, temporarily (like perf-bench.sh): a slow mock Ollama is started on the frontend network and the `api`
# container is recreated with OLLAMA_BASE_URL pointing at it and the per-IP rate limit lifted (the load generator is one
# IP). Both are restored at the end. The test creates a throwaway organization (signup) with its own keys.
# Result: <out>/<label>.json (counts and timings only, no content). See scripts/security/stream-revocation-test.mjs.
set -uo pipefail
cd "$(dirname "$0")/../.."
LABEL=${1:?label}; OUT=${2:-/root/revocation-out}; mkdir -p "$OUT"
NET=sentinel-ai_frontend
TOKENS=${MOCK_STREAM_TOKENS:-400}; TOKEN_MS=${MOCK_TOKEN_MS:-25}

wait_api() { for _ in $(seq 1 90); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q api)" 2>/dev/null)" = healthy ] && return 0; sleep 2; done; echo "api did not become healthy"; return 1; }

docker rm -f mock-ollama >/dev/null 2>&1
docker run -d --name mock-ollama --network "$NET" --network-alias mock-ollama -e MOCK_STREAM_TOKENS="$TOKENS" -e MOCK_TOKEN_MS="$TOKEN_MS" \
  -v "$PWD/scripts/development/perf:/p:ro" node:20-alpine node /p/mock-ollama.mjs 11434 >/dev/null
OLLAMA_BASE_URL=http://mock-ollama:11434 OLLAMA_MODEL=mock RATE_LIMIT_PER_MINUTE=100000000 docker compose up -d --no-deps api >/dev/null 2>&1
wait_api || exit 1

docker run --rm --network "$NET" -v "$PWD/scripts/security:/s:ro" \
  -e LABEL="$LABEL" -e TRIALS="${TRIALS:-24}" -e PARALLEL="${PARALLEL:-4}" -e BG_STREAMS="${BG_STREAMS:-16}" \
  -e REVOKE_AFTER_MS="${REVOKE_AFTER_MS:-1500}" -e MOCK_STREAM_TOKENS="$TOKENS" -e MOCK_TOKEN_MS="$TOKEN_MS" \
  node:20-alpine node /s/stream-revocation-test.mjs > "$OUT/$LABEL.json" 2> "$OUT/$LABEL.err"
code=$?
echo "test exit $code; report $OUT/$LABEL.json"

# restore the gateway exactly as configured in .env
docker compose up -d --no-deps api >/dev/null 2>&1; wait_api
docker rm -f mock-ollama >/dev/null 2>&1
exit $code
