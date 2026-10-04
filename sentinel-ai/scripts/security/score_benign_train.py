"""Score benign TRAINING traffic with the tier-2 classifier, resumably, for threshold calibration (D43).

The first calibration used only deepset's benign train prompts (short questions). The held-out PII evaluation then showed
the classifier flagging 39-54% of ordinary PII-bearing business text as injection. Calibration therefore also needs
benign text of that kind; the ai4privacy TRAIN files (cached by run_data_leakage_evaluation.py --split train) are such
text and contain no injections. Validation splits are never read here.

    python scripts/security/score_benign_train.py --cache ~/.cache/sentinelai-independent-eval --sample 800 \
        --model-dir services/security-engine/models/injection-classifier --out benign-train-scores.jsonl [--max-seconds 540]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "security-engine"))
from app.cascade.classifier import OnnxInjectionClassifier  # noqa: E402

SOURCES = {"ai4privacy-400k-train": "train/400k_train_en.jsonl", "ai4privacy-300k-train": "train/300k_train_en.jsonl"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--model-dir", type=Path, required=True)
    ap.add_argument("--sample", type=int, default=800)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--max-seconds", type=float, default=1e9)
    args = ap.parse_args()
    clf = OnnxInjectionClassifier(args.model_dir, threads=4, max_windows=4)
    done = set()
    if args.out.exists():
        done = {(r["source"], r["line"]) for r in map(json.loads, args.out.read_text(encoding="utf8").splitlines())}
    started = time.monotonic()
    with args.out.open("a", encoding="utf8") as out:
        for name, rel in SOURCES.items():
            path = args.cache / rel
            with open(path, encoding="utf8") as f:
                total = sum(1 for _ in f)
            keep = set(random.Random(20261004).sample(range(total), min(args.sample, total)))
            with open(path, encoding="utf8") as f:
                for i, line in enumerate(f):
                    if i not in keep or (name, i) in done:
                        continue
                    if time.monotonic() - started > args.max_seconds:
                        print(f"time limit: {len(done)} scored so far; run again to resume")
                        return 3
                    d = clf.score_detail(json.loads(line)["source_text"])
                    out.write(json.dumps({"source": name, "line": i, "score": round(d.score, 6),
                                          "partial": d.partial}) + "\n")
                    out.flush()
                    done.add((name, i))
    print(f"done: {len(done)} benign train texts scored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
