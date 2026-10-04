"""Pick the tier-2 threshold and the tier-3 judge band from TRAINING-split scores only (select_injection_classifier.py report).

Rule (fixed before looking at any test split):
  threshold  = the lowest score whose false-positive rate on train benign inputs is <= MAX_FP (classifier decides alone)
  band_high  = the lowest score whose train false-positive rate is <= MAX_FP_HIGH (above it: block without asking the judge)
  band_low   = the lowest score such that at most MAX_JUDGE_RATE of all train inputs fall in [band_low, band_high) (below it:
               allow without asking): the judge band is bounded by cost and latency, not by recall
  (Revised 2026-10-03 on TRAIN data only, before any test split was scored: the first rule, "keep 95% of train attacks
  at or above band_low", put band_low at 0 for the chosen model and would have sent 85% of all traffic to the judge.)
  (Revised 2026-10-04, D43, on TRAIN data only: with --benign-extra, every constraint must hold on EACH benign train
  source separately - deepset's benign prompts AND ai4privacy train text, which the first calibration never saw and on
  which the held-out PII evaluation showed 39-54% false blocks.)
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


def choose_multi(scores: list[float], labels: list[bool], extra: dict[str, list[float]]) -> dict[str, Any]:
    """Like choose(), but every FP / judge-rate limit must hold on each extra benign source too."""
    base = choose(scores, labels)
    sources = {"labelled": (scores, labels), **{k: (v, [False] * len(v)) for k, v in extra.items()}}
    threshold = max(lowest_with_fp(sc, lb, MAX_FP) for sc, lb in sources.values())
    high = max(lowest_with_fp(sc, lb, MAX_FP_HIGH) for sc, lb in sources.values())
    low = max(lowest_within_rate(sc, high, MAX_JUDGE_RATE) for sc, _ in sources.values())
    per_source = {k: {"n": len(sc), "fp_at_threshold": round(fp_rate(sc, lb, threshold), 4),
                      "judge_call_rate": round(sum(low <= x < high for x in sc) / len(sc), 4)} for k, (sc, lb) in sources.items()}
    return {"threshold": threshold, "band_low": low, "band_high": high,
            "train_at_threshold": {"detection_rate": round(recall(scores, labels, threshold), 4),
                                   "false_positive_rate": round(fp_rate(scores, labels, threshold), 4)},
            "train_attacks_in_band": sum(low <= sc < high for sc, y in zip(scores, labels) if y),
            "per_source": per_source, "single_source_choice_was": {k: base[k] for k in ("threshold", "band_low", "band_high")}}


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
    ap.add_argument("--benign-extra", type=Path, help="JSONL from score_benign_train.py (source, score)")
    args = ap.parse_args()
    rep = json.loads(args.report.read_text())
    cand = next(c for c in rep["candidates"] if c["model"] == args.model and c["variant"] == args.variant)
    clean = [n for n, s in cand["splits"].items() if not s["contaminated"]]
    scores = [x for n in clean for x in cand["splits"][n]["scores"]]
    labels = [y for n in clean for y in rep["labels"][n]]
    out = {"model": args.model, "variant": args.variant, "revision": cand["revision"], "chosen_on": clean,
           "rule": {"max_fp": MAX_FP, "max_fp_high": MAX_FP_HIGH, "max_judge_rate": MAX_JUDGE_RATE},
           **(choose_multi(scores, labels, _extra(args.benign_extra)) if args.benign_extra else choose(scores, labels)),
           "per_dataset": {n: {"contaminated": s["contaminated"],
                               "at_chosen_threshold": None} for n, s in cand["splits"].items()}}
    for n, s in cand["splits"].items():
        t = out["threshold"]
        out["per_dataset"][n]["at_chosen_threshold"] = {
            "detection_rate": round(recall(s["scores"], rep["labels"][n], t), 4),
            "false_positive_rate": round(fp_rate(s["scores"], rep["labels"][n], t), 4)}
    print(json.dumps(out, indent=2))


def _extra(path: Path) -> dict[str, list[float]]:
    """JSONL from score_benign_train.py, or the committed JSON form ({"rows": [...]}) in docs/verification/ai-vs-ai/."""
    text = path.read_text(encoding="utf8")
    try:
        rows = json.loads(text)["rows"]
    except (json.JSONDecodeError, TypeError, KeyError):
        rows = [json.loads(x) for x in text.splitlines() if x.strip()]
    out: dict[str, list[float]] = {}
    for r in rows:
        out.setdefault(r["source"], []).append(r["score"])
    return out


if __name__ == "__main__":
    main()
