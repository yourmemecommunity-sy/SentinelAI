"""Estimate the AI judge's cost per 1,000 requests from MEASURED call rates (no API key needed), and the most it could add.

For each held-out test split it runs the real tier-2 classifier, counts the inputs that fall in the judge band (these are
the only ones the judge would see), and prices each call with the real judge prompt (system prompt + nonce-wrapped text)
at a pessimistic 3 characters per token plus `max_tokens` of output, at the judge model's published price. Also reported:
the upper bound on extra detections (attacks in the band = what a perfect judge could catch) and the benign inputs a
judge would have to get right. When a key exists, `ANTHROPIC_USAGE_LEDGER` holds the real spend instead.

    SENTINEL_CLASSIFIER_DIR=services/security-engine/models/injection-classifier \
      python scripts/security/estimate_judge_cost.py --data ~/.cache/sentinelai-independent-eval
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "security-engine"))

from app.cascade.budget import CHARS_PER_TOKEN_ESTIMATE, PRICES_PER_MTOK  # noqa: E402
from app.cascade.classifier import OnnxInjectionClassifier  # noqa: E402
from app.cascade.judge import DEFAULT_JUDGE_MODEL, SYSTEM_PROMPT, build_user_message  # noqa: E402
from app.config.settings import Settings  # noqa: E402

SPLITS = {"deepset/prompt-injections": ("deepset__prompt-injections__test.json", "text", lambda r: r["label"] == 1),
          "jackhhao/jailbreak-classification": ("jackhhao__jailbreak-classification__test.json", "prompt",
                                                lambda r: r["type"] == "jailbreak")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--max-output-tokens", type=int, default=200)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    s = Settings()
    clf = OnnxInjectionClassifier(Path(os.environ.get("SENTINEL_CLASSIFIER_DIR", s.classifier_dir)), threads=4,
                                  max_windows=s.classifier_max_windows)
    if not clf.healthy():
        raise SystemExit(f"classifier unavailable: {clf.load_error}")
    price_in, price_out = PRICES_PER_MTOK[DEFAULT_JUDGE_MODEL]
    report: dict[str, object] = {"model": DEFAULT_JUDGE_MODEL, "band": [s.judge_band_low, s.judge_band_high],
                                 "chars_per_token": CHARS_PER_TOKEN_ESTIMATE, "splits": {}}
    for name, (file, field, attack) in SPLITS.items():
        rows = json.loads((args.data / file).read_text(encoding="utf8"))
        calls = atk_in = ben_in = 0
        in_tokens = 0
        for r in rows:
            d = clf.score_detail(r[field])
            in_band = s.judge_band_low <= d.score < s.judge_band_high or (d.partial and d.score < s.judge_band_high)
            if not in_band:
                continue
            calls += 1
            atk_in += attack(r)
            ben_in += not attack(r)
            in_tokens += int((len(SYSTEM_PROMPT) + len(build_user_message(r[field], "0" * 16))) / CHARS_PER_TOKEN_ESTIMATE)
        rate = calls / len(rows)
        per_call = (in_tokens / max(calls, 1) * price_in + args.max_output_tokens * price_out) / 1e6
        report["splits"][name] = {  # type: ignore[index]
            "requests": len(rows), "judge_calls": calls, "judge_call_rate": round(rate, 4),
            "attacks_in_band": atk_in, "benign_in_band": ben_in,
            "mean_input_tokens_per_call": round(in_tokens / max(calls, 1)),
            "usd_per_call_upper_bound": round(per_call, 6),
            "usd_per_1000_requests_judge_on": round(rate * 1000 * per_call, 4),
            "usd_per_1000_requests_judge_off": 0.0,
        }
        print(name, json.dumps(report["splits"][name]))  # type: ignore[index]
    if args.out:
        args.out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
