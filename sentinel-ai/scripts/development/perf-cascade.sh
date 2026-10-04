#!/usr/bin/env bash
# Before/after benchmark for the detection cascade (k6, instant mock provider, the running compose stack). Recreates
# ONLY the security engine for each configuration, runs the same perf-bench.sh subset, and restores the engine exactly
# as configured at the end (also on failure).
#
#   bash scripts/development/perf-cascade.sh [seconds per run, default 20] [config ...]
#   configs: tier1, tier1-w2 (cascade off - development mode, benchmark only), cascade-w1, cascade-w2 (2 workers, 3 GiB)
#
# Results: $ROOT_OUT (default /root/perf-cascade)/<config>/ (k6 summaries + results.json) and a combined table on stdout.
set -uo pipefail
cd "$(dirname "$0")/../.."
SECS=${1:-20}; shift || true
CONFIGS=("${@:-tier1 cascade-w1 cascade-w2}")
[ ${#CONFIGS[@]} -eq 1 ] && read -r -a CONFIGS <<< "${CONFIGS[0]}"
ROOT_OUT=${ROOT_OUT:-/root/perf-cascade}; mkdir -p "$ROOT_OUT"   # not /tmp: survives a WSL VM restart
OVR=$(mktemp /tmp/perf-override-XXXX.yml)

restore() { rm -f "$OVR"; docker compose up -d --no-deps security-engine >/dev/null 2>&1; }
trap restore EXIT

wait_engine() {
  for _ in $(seq 1 120); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q security-engine)" 2>/dev/null)" = healthy ] && return 0; sleep 2
  done; echo "engine did not become healthy"; return 1
}

for cfg in "${CONFIGS[@]}"; do
  case "$cfg" in
    # The cascade is mandatory in production (D30), so the "before" engine runs in development mode for this benchmark
    # only; its token and digest key stay set, so requests take the same authenticated path.
    tier1) printf 'services:\n  security-engine:\n    environment:\n      SENTINEL_ENV: development\n      SENTINEL_CASCADE: "off"\n' > "$OVR" ;;
    tier1-w2) printf 'services:\n  security-engine:\n    environment:\n      SENTINEL_ENV: development\n      SENTINEL_CASCADE: "off"\n      SECURITY_ENGINE_WORKERS: "2"\n' > "$OVR" ;;
    cascade-w1) printf 'services:\n  security-engine:\n    environment:\n      SECURITY_ENGINE_WORKERS: "1"\n' > "$OVR" ;;
    cascade-w2) printf 'services:\n  security-engine:\n    mem_limit: 3g\n    environment:\n      SECURITY_ENGINE_WORKERS: "2"\n' > "$OVR" ;;
    *) echo "unknown config $cfg"; exit 2 ;;
  esac
  echo "### $cfg"
  docker compose -f docker-compose.yml -f "$OVR" up -d --no-deps security-engine >/dev/null 2>&1
  wait_engine || exit 1
  docker compose exec -T security-engine sh -c 'echo cascade=${SENTINEL_CASCADE:-default} env=$SENTINEL_ENV workers=${SECURITY_ENGINE_WORKERS:-1}'
  OUT="$ROOT_OUT/$cfg" TARGETS="${TARGETS:-scan chat}" VUS_LIST="${VUS_LIST:-1 8}" bash scripts/development/perf-bench.sh "$SECS" | sed -n '/^## Results/,/^## Gateway/p' | head -8
  docker stats --no-stream --format '{{.Name}} mem {{.MemUsage}}' "$(docker compose ps -q security-engine)"
done

python3 - "$ROOT_OUT" "${CONFIGS[@]}" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1]); cfgs = sys.argv[2:]
print("\n## Combined (ms; req/s)")
print("| config | run | p50 | p95 | p99 | req/s | ok |")
print("|---|---|---|---|---|---|---|")
for c in cfgs:
    f = root / c / "results.json"
    if not f.exists():
        print(f"| {c} | (no results) |"); continue
    for run, r in json.load(open(f)).items():
        print(f"| {c} | {run} | {r['p50']:.1f} | {r['p95']:.1f} | {r['p99']:.1f} | {r['rps']:.1f} | {r['ok']*100:.1f}% |")
PY
