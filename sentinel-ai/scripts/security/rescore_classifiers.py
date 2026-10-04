"""Re-score classifier candidates on the TRAINING splits with full-coverage windowing, resumably.

Why: the first selection run (select_injection_classifier.py, 2026-10-03) relied on the tokenizers library's `overflowing`
output, which does not return every window of a long input (a 4,002-token text came back as 512 + 68 tokens), so long
prompts were only partly scored. This script scores every window (the same hand-built windows the engine uses), appends
each score to a JSONL cache so an interrupted run resumes where it stopped, and writes a report in the
select_injection_classifier.py format for choose_thresholds.py.

    python scripts/security/rescore_classifiers.py --data ~/.cache/sentinelai-independent-eval --cache scores.jsonl \
        --candidate "protectai/deberta-v3-base-prompt-injection-v2|fp32|<dir with model.onnx, tokenizer.json, config.json>" \
        --candidate "fmops/distilbert-prompt-injection|int8|<dir>|model.int8.onnx" --out report.json [--max-seconds 540]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("select_injection_classifier", HERE / "select_injection_classifier.py")
sel = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(sel)  # type: ignore[union-attr]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--candidate", action="append", required=True, help="model_id|variant|dir[|onnx file name]")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--max-seconds", type=float, default=1e9, help="stop after this long (resume later)")
    ap.add_argument("--threads", type=int, default=4)
    args = ap.parse_args()
    started = time.monotonic()
    data = {}
    for name, (file, field, is_attack) in sel.DATASETS.items():
        rows = json.loads((args.data / file).read_text(encoding="utf8"))
        data[name] = ([r[field] for r in rows], [bool(is_attack(r)) for r in rows])
    done: dict[tuple[str, str, str, int], float] = {}
    if args.cache.exists():
        for line in args.cache.read_text(encoding="utf8").splitlines():
            r = json.loads(line)
            done[(r["model"], r["variant"], r["dataset"], r["i"])] = r["score"]
    finished = True
    with args.cache.open("a", encoding="utf8") as cache:
        for spec_s in args.candidate:
            model, variant, folder, *rest = spec_s.split("|", 3)
            d = Path(folder)
            cfg = json.loads((d / "config.json").read_text())
            clf = sel.Classifier(d / (rest[0] if rest else "model.onnx"), d / "tokenizer.json",
                                 sel.injection_index(cfg.get("id2label")), threads=args.threads)
            for name, (texts, _) in data.items():
                for i, text in enumerate(texts):
                    if (model, variant, name, i) in done:
                        continue
                    if time.monotonic() - started > args.max_seconds:
                        finished = False
                        break
                    s = clf.score(text)
                    done[(model, variant, name, i)] = s
                    cache.write(json.dumps({"model": model, "variant": variant, "dataset": name, "i": i, "score": s}) + "\n")
                    cache.flush()
    total = sum(len(t) for t, _ in data.values()) * len(args.candidate)
    print(f"scored {len(done)} of {total}" + ("" if finished else " (time limit reached; run again to resume)"))
    if not finished or len(done) < total:
        return 3
    report: dict[str, Any] = {"labels": {n: data[n][1] for n in data}, "candidates": [], "windowing": "full coverage (fixed)"}
    for spec_s in args.candidate:
        model, variant = spec_s.split("|")[:2]
        meta = next(c for c in sel.CANDIDATES if c["id"] == model)
        splits = {}
        for name, (texts, labels) in data.items():
            scores = [done[(model, variant, name, i)] for i in range(len(texts))]
            splits[name] = {"contaminated": name in meta["trained_on"], "auc": round(sel.auc(scores, labels), 4),
                            "at_0.5": sel.rates(scores, labels, 0.5), "scores": [round(s, 5) for s in scores]}
        report["candidates"].append({"model": model, "variant": variant, "revision": "see classifier.json / selection run",
                                     "licence": meta["licence"], "trained_on": meta["trained_on"], "splits": splits})
    args.out.write_text(json.dumps(report))
    print(f"report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
