"""Streams through the Python SDK against the REAL containerized gateway and a REAL model (Ollama).

The SDK's own suite uses protocol-faithful HTTP test servers; this checks that the SDK and the actual gateway agree.

    docker run --rm --network sentinel-ai_frontend -e OLLAMA_MODEL=... -e SENTINEL_KEY=snl_... \
      -v "$PWD/packages/sdk/python:/py:ro" -v "$PWD/scripts/development:/s:ro" -e PYTHONPATH=/py \
      python:3.12-slim python /s/sdk_stream_verify.py
"""

import os
import sys

from sentinelai import Sentinel, SentinelBlockedError, SentinelError

API = os.environ.get("API_URL", "http://api:4000")
MODEL = os.environ.get("OLLAMA_MODEL")
KEY = os.environ.get("SENTINEL_KEY")
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"  # runtime-assembled, not a real credential
failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        failures += 1


if not MODEL or not KEY:
    print("SKIP OLLAMA_MODEL or SENTINEL_KEY not set")
    sys.exit(3)

# Plain http is refused by default (the key would travel in clear text); this is a private Docker network.
client = Sentinel(api_key=KEY, base_url=API, timeout=120, allow_insecure_http=True)

with client.stream("ollama", [{"role": "user", "content": "Say hello to jane.doe@example.com in one short sentence."}],
                   model=MODEL, max_output_tokens=30, session_id="sdk-verify-py") as st:
    parts = list(st)
summary = st.summary
check("Python SDK streams from the real gateway and a real model", len(parts) > 0 and len("".join(parts)) > 0, f"{len(parts)} deltas")
check("the summary reports the real model and both security verdicts",
      summary is not None and summary.model == MODEL and bool(summary.security.input.event_id) and bool(summary.security.output.event_id),
      f"model={getattr(summary, 'model', None)}")
check("PII in the prompt was TOKENIZED before the model saw it", summary is not None and summary.security.input.decision == "TOKENIZE",
      getattr(getattr(getattr(summary, "security", None), "input", None), "decision", None) or "")

err = None
try:
    client.stream("ollama", [{"role": "user", "content": f"deploy with {AWS}"}], model=MODEL).text()
except SentinelError as e:  # noqa: BLE001 - the type is asserted below
    err = e
check("a secret in a streamed prompt raises SentinelBlockedError (input stage)",
      isinstance(err, SentinelBlockedError) and getattr(err, "stage", None) == "input", type(err).__name__ if err else "no error")

sys.exit(0 if failures == 0 else 1)
