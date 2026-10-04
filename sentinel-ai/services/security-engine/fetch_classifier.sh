#!/usr/bin/env sh
# Downloads the tier-2 prompt-injection classifier chosen in docs/verification/12-ai-vs-ai.md, pinned to a Hugging Face
# commit, and verifies every file by SHA-256 before writing classifier.json (which the engine checks again at load time).
#   sh services/security-engine/fetch_classifier.sh <target-dir>
# Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), ONNX export published by the model authors.
set -eu
DEST="${1:?usage: fetch_classifier.sh <target-dir>}"
REPO="protectai/deberta-v3-base-prompt-injection-v2"
REV="90c9989b1a342275dd0d1a95aad283c04e075671"
BASE="https://huggingface.co/${REPO}/resolve/${REV}/onnx"
ONNX_SHA256="${CLASSIFIER_ONNX_SHA256:-f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c}"
TOKENIZER_SHA256="${CLASSIFIER_TOKENIZER_SHA256:-752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f}"

mkdir -p "$DEST"
fetch() { curl -fsSL --retry 3 -o "$DEST/$2" "$BASE/$1"; }
fetch model.onnx model.onnx
fetch tokenizer.json tokenizer.json
fetch config.json config.json

check() {  # file expected-sha (empty = record only, used once to pin)
  got=$(sha256sum "$DEST/$1" | cut -d' ' -f1)
  if [ -n "$2" ] && [ "$got" != "$2" ]; then echo "SHA-256 mismatch for $1: $got" >&2; exit 1; fi
  echo "$got"
}
onnx_sha=$(check model.onnx "$ONNX_SHA256")
tok_sha=$(check tokenizer.json "$TOKENIZER_SHA256")

# The injection class index comes from the model's own config (id2label), not from an assumption.
index=$(python3 -c "import json,sys; c=json.load(open(sys.argv[1])); print(next(int(k) for k,v in c['id2label'].items() if v.upper() in ('INJECTION','LABEL_1')))" "$DEST/config.json")
cat > "$DEST/classifier.json" <<EOF
{"model_id": "${REPO}", "revision": "${REV}", "variant": "fp32", "licence": "apache-2.0",
 "onnx_sha256": "${onnx_sha}", "tokenizer_sha256": "${tok_sha}", "injection_index": ${index}}
EOF
echo "classifier ready in ${DEST} (model.onnx sha256 ${onnx_sha})"
