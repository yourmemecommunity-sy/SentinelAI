#!/usr/bin/env bash
# Runs select_injection_classifier.py in a detached python:3.12 container (inside WSL/Linux, Docker required), so a long
# run survives the terminal. Train splits are read from the evaluation cache; only the JSON report is written (to $1).
#   MODELS=id1,id2 bash scripts/security/run-classifier-selection.sh /root/report.json    # MODELS optional (default: all)
#   docker logs -f sentinel-classifier-selection
set -euo pipefail
cd "$(dirname "$0")/../.."
DATA="${EVAL_CACHE:-/mnt/c/Users/Shivam dubey/.cache/sentinelai-independent-eval}"
OUT="${1:-/tmp/classifier-selection.json}"
docker volume create sentinel-ml-cache >/dev/null
docker rm -f sentinel-classifier-selection >/dev/null 2>&1 || true
docker run -d --name sentinel-classifier-selection -v "$PWD:/repo:ro" -v "$DATA:/data:ro" -v sentinel-ml-cache:/cache \
  -v "$(dirname "$OUT"):/out" -e HF_HOME=/cache/hf -e PIP_CACHE_DIR=/cache/pip -e MODELS="${MODELS:-}" \
  -e OUT_NAME="$(basename "$OUT")" python:3.12-slim bash -c '
    set -e
    [ -x /cache/venv/bin/python ] || python -m venv /cache/venv
    /cache/venv/bin/pip install -q --disable-pip-version-check torch --index-url https://download.pytorch.org/whl/cpu
    /cache/venv/bin/pip install -q --disable-pip-version-check "transformers<5" "optimum[onnxruntime]" onnxruntime tokenizers numpy psutil huggingface_hub
    /cache/venv/bin/python /repo/scripts/security/select_injection_classifier.py --data /data --work /cache/candidates \
      --out "/out/$OUT_NAME" --models "$MODELS"'
