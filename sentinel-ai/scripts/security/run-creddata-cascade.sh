#!/usr/bin/env bash
# Samsung CredData (secrets) evaluation, tier 1 vs cascade, in a detached container built from the security-engine image
# (all engine dependencies + the pinned classifier). Inside WSL/Linux with Docker; CredData built per
# docs/verification/10-pii-secrets-evaluation.md. Results: $OUT/creddata-{tier1,cascade}.json
#   bash scripts/security/run-creddata-cascade.sh [/root/creddata] [/root/eval-out-v2]
#   docker logs -f sentinel-creddata-eval
set -euo pipefail
cd "$(dirname "$0")/../.."
CRED="${1:-/root/creddata}"; OUT="${2:-/root/eval-out-v2}"; mkdir -p "$OUT"; chmod 777 "$OUT"
docker rm -f sentinel-creddata-eval >/dev/null 2>&1 || true
docker run -d --name sentinel-creddata-eval -v "$PWD:/repo:ro" -v "$CRED:/creddata:ro" -v "$OUT:/out" -w /repo/services/security-engine \
  -e SENTINEL_CLASSIFIER_DIR=/srv/models/injection-classifier --entrypoint sh sentinel-ai/security-engine:local -c '
    python ../../scripts/security/run_data_leakage_evaluation.py --suite secrets --creddata /creddata --report /out/creddata-tier1.json \
      > /out/creddata-tier1.log 2>&1
    SENTINEL_CASCADE=on python ../../scripts/security/run_data_leakage_evaluation.py --suite secrets --creddata /creddata \
      --report /out/creddata-cascade.json > /out/creddata-cascade.log 2>&1
    echo done > /out/creddata.done'
echo "started; results in $OUT"
