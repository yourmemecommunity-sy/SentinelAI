"""Pick the tier-2 threshold and the tier-3 judge band from TRAINING-split scores only (select_injection_classifier.py report).

Rule (fixed before looking at any test split):
  threshold  = the lowest score whose false-positive rate on train benign inputs is <= MAX_FP (classifier decides alone)
  band_high  = the lowest score whose train false-positive rate is <= MAX_FP_HIGH (above it: block without asking the judge)
  band_low   = the lowest score such that at most MAX_JUDGE_RATE of all train inputs fall in [band_low, band_high) (below it:
               allow without asking): the judge band is bounded by cost and latency, not by recall
  (Revised 2026-10-03 on TRAIN data only, before any test split was scored: the first rule, "keep 95% of train attacks
  at or above band_low", put band_low at 0 for the chosen model and would have sent 85% of all traffic to the judge.)
The judge is asked only for scores in [band_low, band_high). The judge call rate on train inputs is reported, because it
drives cost and latency.

Each dataset a candidate was trained on is CONTAMINATED for that candidate (its train split may be memorised), so the
report shows every number per dataset with that flag, and the headline uses only uncontaminated data.

    python scripts/security/choose_thresholds.py classifier-selection.json --model fmops/distilbert-prompt-injection --variant int8
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

MAX_FP = 0.02
MAX_FP_HIGH = 0.005
MAX_JUDGE_RATE = 0.20


def fp_rate(scores: list[float], labels: list[bool], t: float) -> float:
    neg = [s for s, y in zip(scores, labels) if not y]
    return sum(s >= t for s in neg) / len(neg) if neg else 0.0


def recall(scores: list[float], labels: list[bool], t: float) -> float:
    pos = [s for s, y in zip(scores, labels) if y]
    return sum(s >= t for s in pos) / len(pos) if pos else 0.0


def lowest_with_fp(scores: list[float], labels: list[bool], max_fp: float) -> float:
    for t in sorted(set(scores) | {1.0}):
        if fp_rate(scores, labels, t) <= max_fp:
            return round(t, 5)
    return 1.0


def lowest_within_rate(scores: list[float], high: float, max_rate: float) -> float:
    best = high
    for t in sorted({s for s in scores if s < high}, reverse=True):
        if sum(t <= s < high for s in scores) / len(scores) > max_rate:
            break
        best = t
    return round(best, 5)


def choose(scores: list[float], labels: list[bool]) -> dict[str, Any]:
    threshold = lowest_with_fp(scores, labels, MAX_FP)
    high = lowest_with_fp(scores, labels, MAX_FP_HIGH)
    low = lowest_within_rate(scores, high, MAX_JUDGE_RATE)
    in_band = sum(low <= s < high for s in scores) / len(scores)
    return {"threshold": threshold, "band_low": low, "band_high": high,
            "train_at_threshold": {"detection_rate": round(recall(scores, labels, threshold), 4),
                                   "false_positive_rate": round(fp_rate(scores, labels, threshold), 4)},
            "train_judge_call_rate": round(in_band, 4),
            "train_attacks_in_band": sum(low <= sc < high for sc, y in zip(scores, labels) if y),
            "train_benign_in_band": sum(low <= sc < high for sc, y in zip(scores, labels) if not y)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--model", required=True)
    ap.add_argument("--variant", default="fp32")
    args = ap.parse_args()
    rep = json.loads(args.report.read_text())
    cand = next(c for c in rep["candidates"] if c["model"] == args.model and c["variant"] == args.variant)
    clean = [n for n, s in cand["splits"].items() if not s["contaminated"]]
    scores = [x for n in clean for x in cand["splits"][n]["scores"]]
    labels = [y for n in clean for y in rep["labels"][n]]
    out = {"model": args.model, "variant": args.variant, "revision": cand["revision"], "chosen_on": clean,
           "rule": {"max_fp": MAX_FP, "max_fp_high": MAX_FP_HIGH, "max_judge_rate": MAX_JUDGE_RATE}, **choose(scores, labels),
           "per_dataset": {n: {"contaminated": s["contaminated"],
                               "at_chosen_threshold": None} for n, s in cand["splits"].items()}}
    for n, s in cand["splits"].items():
        t = out["threshold"]
        out["per_dataset"][n]["at_chosen_threshold"] = {
            "detection_rate": round(recall(s["scores"], rep["labels"][n], t), 4),
            "false_positive_rate": round(fp_rate(s["scores"], rep["labels"][n], t), 4)}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
