# Dataset Schema (version 1.0)

One JSON object per line (`.jsonl`), UTF-8, under `datasets/<category>/...`.

```json
{
  "id": "pii_email_000001",
  "category": "PII",
  "subcategory": "EMAIL",
  "text": "Contact alex.abcd12@example.com for details",
  "entities": [{"type": "EMAIL", "start": 8, "end": 32}],
  "severity": "MEDIUM",
  "expected_action": "MASK",
  "source": "synthetic",
  "version": "1.0",
  "critical": true,
  "direction": "INPUT"
}
```

| Field | Rule |
|---|---|
| `id` | unique across all files |
| `category` / `subcategory` | e.g. `PII/EMAIL`, `SECRETS/JWT`, `PROMPT_INJECTION/OBFUSCATED_ROT13`, `BENIGN/GENERAL` |
| `entities[]` | `type` is an engine `EntityType`; `start`/`end` are character offsets into `text` with `0 <= start < end <= len(text)` |
| `expected_action` | `ALLOW MASK REDACT TOKENIZE HASH QUARANTINE BLOCK` under the **baseline** policy |
| `source` | `synthetic` or `licensed:<dataset name>`; anything else fails the gate. Real credentials/people/accounts are forbidden |
| `version` | dataset version, tracked in `datasets/manifest.json` with per-file SHA-256 |
| `critical` | (extension) gating flag; critical cases must pass 100% |
| `direction` | (extension) `INPUT` (default) or `OUTPUT` for output-leakage cases |

Files are produced by `scripts/dataset/generate_synthetic_datasets.py` (seeded, deterministic). Secret-shaped values are random strings in real formats - not real credentials.

## Secret-shaped values are stored defanged

Values of secret-type entities (`API_KEY`, `AWS_CREDENTIAL`, `GITHUB_TOKEN`, `GOOGLE_CREDENTIAL`, `JWT`, `OAUTH_TOKEN`,
`PASSWORD`, `PRIVATE_KEY`, `CONNECTION_STRING`, `HIGH_ENTROPY_SECRET`) are **stored** split into 8-character chunks joined
by the inert marker `[FAKE]`:

```
stored:  Use this key: sk_live_[FAKE]XXXXXXXX[FAKE]XXXXXXXX[FAKE]XXXXXXXX
```

The materialized form is that text with every `[FAKE]` removed. It exists only in memory while the evaluator runs and
is never written anywhere - including in this document, which is why no example of it is shown.

* Stored verbatim, synthetic keys are indistinguishable from real ones to secret scanners (GitHub push protection
  rightly blocks them) and to people. With the marker, no credential pattern can match and the file says what it is.
* `run_evaluation.py` materializes the realistic value in memory (removes the marker) before scanning, so the engine is
  graded on exactly the same strings as before. **`entities[].start/end` refer to the materialized text**, not the stored
  line.
* The evaluator refuses to run if any stored text contains a verbatim credential pattern, so a regeneration that skipped
  defanging fails CI instead of reaching the repository.
* Always read datasets through `run_evaluation.load_records()` (or `scripts/dataset/defang.materialize`). Reading the raw
  JSONL directly gives the stored form, whose offsets will not line up.

Implementation: `scripts/dataset/defang.py`.
