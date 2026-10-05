#!/usr/bin/env bash
# Samsung CredData (secrets) evaluation, tier 1 vs cascade, in a detached container built from the security-engine image
# (all engine dependencies + the pinned classifier). Inside WSL/Linux with Docker; CredData built per
# docs/verification/10-pii-secrets-evaluation.md. Results: $OUT/creddata-{tier1,cascade}.json, then $OUT/creddata.done
#   bash scripts/security/run-creddata-cascade.sh [/root/creddata] [/root/eval-out-v2]
#   SHARDS=3 bash scripts/security/run-creddata-cascade.sh ...   # N parallel engine processes (~1.5 GiB each)
#   tail -f /root/eval-out-v2/creddata-cascade*.log               # "progress ..." lines every 1,000 lines with an ETA
#
# Robust to crashes, WSL/Docker restarts and laptop sleep: every run checkpoints every 1,000 lines
# ($OUT/creddata-cascade[.shardK].partial.json) and resumes from there; the container has a restart policy and re-runs
# the same idempotent command (finished steps are skipped). Running this script again also resumes; delete the
# .partial.json files to start over. The container stays up (idle) after finishing; remove it with
# `docker rm -f sentinel-creddata-eval`.
set -euo pipefail
cd "$(dirname "$0")/../.."
CRED="${1:-/root/creddata}"; OUT="${2:-/root/eval-out-v2}"; SHARDS="${SHARDS:-1}"
mkdir -p "$OUT"; chmod 777 "$OUT"
docker rm -f sentinel-creddata-eval >/dev/null 2>&1 || true
docker run -d --name sentinel-creddata-eval --restart unless-stopped \
  -v "$PWD:/repo:ro" -v "$CRED:/creddata:ro" -v "$OUT:/out" -w /repo/services/security-engine \
  -e SENTINEL_CLASSIFIER_DIR=/srv/models/injection-classifier -e SHARDS="$SHARDS" \
  --entrypoint sh sentinel-ai/security-engine:local -c '
    EVAL=../../scripts/security/run_data_leakage_evaluation.py
    echo "container (re)started $(date -u +%FT%TZ), shards=$SHARDS" >> /out/creddata-cascade.log
    if [ ! -f /out/creddata-tier1.json ]; then
      python $EVAL --suite secrets --creddata /creddata --report /out/creddata-tier1.json >> /out/creddata-tier1.log 2>&1 || exit 1
    fi
    if [ ! -f /out/creddata-cascade.json ]; then
      if [ "$SHARDS" = 1 ]; then
        SENTINEL_CASCADE=on python $EVAL --suite secrets --creddata /creddata --checkpoint /out/creddata-cascade.partial.json \
          --report /out/creddata-cascade.json >> /out/creddata-cascade.log 2>&1 || exit 1
      else
        pids=""; parts=""
        for k in $(seq 0 $((SHARDS - 1))); do
          SENTINEL_CASCADE=on python $EVAL --suite secrets --creddata /creddata --shard "$k/$SHARDS" \
            --checkpoint "/out/creddata-cascade.shard$k.partial.json" >> "/out/creddata-cascade.shard$k.log" 2>&1 &
          pids="$pids $!"; parts="$parts /out/creddata-cascade.shard$k.partial.json"
        done
        for p in $pids; do wait "$p" || exit 1; done
        python $EVAL --suite secrets --creddata /creddata --merge $parts --report /out/creddata-cascade.json \
          >> /out/creddata-cascade.log 2>&1 || exit 1
      fi
    fi
    echo done > /out/creddata.done
    exec sleep infinity'
echo "started (shards=$SHARDS); progress: tail -f $OUT/creddata-cascade*.log"
