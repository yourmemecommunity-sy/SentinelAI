#!/usr/bin/env bash
# Gateway overhead benchmark (k6) against the running compose stack, with an INSTANT mock provider so only the gateway +
# security engine (+ audit writes) are measured. Run from the repository root inside WSL/Linux with the stack up:
#
#   bash scripts/development/perf-bench.sh [seconds per run, default 30]
#   TARGETS="scan chat" VUS_LIST="1 8" bash scripts/development/perf-bench.sh 20     # a subset (default: all)
#
# What it changes, temporarily: the `api` container is recreated with OLLAMA_BASE_URL pointing at the mock and the
# per-IP rate limit lifted (a load generator is one IP; the limiter would answer 429 and measure nothing). Both are
# restored at the end. Nothing else in the stack is touched. Results: $OUT (default /tmp/perf-bench).
set -uo pipefail
cd "$(dirname "$0")/../.."
SECS=${1:-30}
OUT=${OUT:-/tmp/perf-bench}; rm -rf "$OUT"; mkdir -p "$OUT"; chmod 777 "$OUT"   # k6 runs as a non-root user
NET=sentinel-ai_frontend
PERF="$PWD/scripts/development/perf"
m0=$(cut -d' ' -f1 /proc/uptime); w0=$(date +%s)

wait_api() { for _ in $(seq 1 90); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q api)" 2>/dev/null)" = healthy ] && return 0; sleep 2; done; echo "api did not become healthy"; return 1; }

echo "## Hardware / software"
echo "CPU: $(lscpu | sed -n 's/^Model name: *//p') — $(nproc) vCPU visible to the Docker VM; RAM $(free -g | awk '/Mem/{print $2}') GiB"
echo "Docker $(docker version --format '{{.Server.Version}}'); every component (load generator, gateway, engine, Postgres, vault, mock) shares this one machine"
echo

docker rm -f mock-ollama >/dev/null 2>&1
docker run -d --name mock-ollama --network "$NET" --network-alias mock-ollama -v "$PERF:/p:ro" node:20-alpine node /p/mock-ollama.mjs 11434 >/dev/null
OLLAMA_BASE_URL=http://mock-ollama:11434 OLLAMA_MODEL=mock RATE_LIMIT_PER_MINUTE=100000000 docker compose up -d --no-deps api >/dev/null 2>&1
wait_api || exit 1

k6() {  # <name> <target> <vus> <duration>
  docker run --rm --network "$NET" -v "$PERF:/p:ro" -v "$OUT:/out" grafana/k6:0.54.0 run --quiet \
    -e TARGET="$2" -e VUS="$3" -e DURATION="$4" --summary-export "/out/$1.json" /p/gateway-bench.js > "$OUT/$1.log" 2>&1
  echo "  $1: exit $?"
}

echo "## Warm-up (discarded)"; k6 warmup chat 4 10s
echo "## Measured runs (${SECS}s each)"
for vus in ${VUS_LIST:-1 8 32}; do
  for target in ${TARGETS:-direct chat chat_pii scan}; do k6 "${target}_vu${vus}" "$target" "$vus" "${SECS}s"; done
done

# restore the gateway exactly as configured in .env
docker compose up -d --no-deps api >/dev/null 2>&1; wait_api
docker rm -f mock-ollama >/dev/null 2>&1

python3 - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
rows = {}
for f in sorted(out.glob("*_vu*.json")):
    d = json.load(open(f))
    m = d["metrics"]
    dur, reqs, chk = m["http_req_duration"], m["http_reqs"], m.get("checks", {})
    rows[f.stem] = {"p50": dur["med"], "p95": dur["p(95)"], "p99": dur["p(99)"], "max": dur["max"], "rps": reqs["rate"], "n": reqs["count"],
                    "ok": chk.get("value", chk.get("rate")), "fails": chk.get("fails", 0)}
print("\n## Results (latency in ms as seen by the client; rps = completed requests per second)")
print("| run | requests | ok checks | p50 | p95 | p99 | max | req/s |")
print("|---|---|---|---|---|---|---|---|")
for k, r in rows.items():
    print(f"| {k} | {r['n']} | {r['ok']*100:.2f}% ({r['fails']} failed) | {r['p50']:.2f} | {r['p95']:.2f} | {r['p99']:.2f} | {r['max']:.1f} | {r['rps']:.1f} |")
print("\n## Gateway overhead = gateway path minus the direct provider hop (same concurrency)")
print("| concurrency | path | p50 overhead | p95 overhead | p99 overhead |")
print("|---|---|---|---|---|")
for vus in (1, 8, 32):
    base = rows.get(f"direct_vu{vus}")
    for path in ("chat", "chat_pii"):
        r = rows.get(f"{path}_vu{vus}")
        if base and r:
            print(f"| {vus} | {path} | {r['p50']-base['p50']:.2f} | {r['p95']-base['p95']:.2f} | {r['p99']-base['p99']:.2f} |")
json.dump(rows, open(out / "results.json", "w"), indent=2)
PY
echo; echo "## Non-OK responses (status + reason), if any"; grep -h "NOT-OK" "$OUT"/*_vu*.log | sed -e 's/.*NOT-OK/NOT-OK/' -e 's/ vu=[0-9]*//' -e 's/ duration_ms=[0-9]*//' -e 's/\"*$//' | cut -c1-200 | sort | uniq -c | sort -rn | head -20
echo; echo "wall $(( $(date +%s)-w0 ))s vs VM uptime delta $(python3 -c "print(int($(cut -d' ' -f1 /proc/uptime)-$m0))")s (equal = no suspend during the run)"
