"""Choose the Tier-2 prompt-injection classifier, measured on TRAINING splits only.

Candidates are open-source Hugging Face models; each is exported to ONNX (when the repository has no ONNX file) and run
with onnxruntime exactly as the engine would run it: tokenizer.json + ONNX, CPU only, long inputs scored in overlapping
512-token windows (max score over windows, never truncated). Every candidate is measured in fp32 and with int8 dynamic
quantisation.

Reported per candidate and train split: detection rate and false-positive rate at threshold 0.5, ROC AUC, single-thread
latency p50/p95 per prompt, resident memory after loading, file size. Training-data CONTAMINATION is reported from each
model card: a model trained on a benchmark scores optimistically on it, even on its train split.

Run (needs: onnxruntime tokenizers numpy psutil huggingface_hub; plus torch transformers optimum[onnxruntime] to export):
    python scripts/security/select_injection_classifier.py --data ~/.cache/sentinelai-independent-eval --out report.json
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any

import numpy as np

CANDIDATES: list[dict[str, Any]] = [
    {"id": "protectai/deberta-v3-base-prompt-injection-v2", "onnx": "onnx/model.onnx", "tokenizer": "onnx/tokenizer.json",
     "licence": "apache-2.0", "trained_on": ["jackhhao/jailbreak-classification"]},
    {"id": "fmops/distilbert-prompt-injection", "onnx": None, "tokenizer": "tokenizer.json",
     "licence": "apache-2.0", "trained_on": ["deepset/prompt-injections"]},
    {"id": "deepset/deberta-v3-base-injection", "onnx": None, "tokenizer": "tokenizer.json",
     "licence": "mit", "trained_on": ["deepset/prompt-injections"]},
]
DATASETS = {
    "deepset/prompt-injections": ("deepset__prompt-injections__train.json", "text", lambda r: r["label"] == 1),
    "jackhhao/jailbreak-classification": ("jackhhao__jailbreak-classification__train.json", "prompt",
                                          lambda r: r["type"] == "jailbreak"),
}
MAX_LEN, STRIDE = 512, 64


def rss_mib() -> float:
    import psutil
    return psutil.Process(os.getpid()).memory_info().rss / 2**20


def prepare(cand: dict[str, Any], work: Path) -> tuple[Path, Path, dict[str, Any]]:
    """Download (pinned to the current commit) and export to ONNX if needed. Returns (onnx, tokenizer, meta)."""
    from huggingface_hub import HfApi, hf_hub_download, snapshot_download
    sha = HfApi().model_info(cand["id"]).sha
    target = work / cand["id"].replace("/", "__")
    if cand["onnx"]:
        onnx = Path(hf_hub_download(cand["id"], cand["onnx"], revision=sha))
        tok = Path(hf_hub_download(cand["id"], cand["tokenizer"], revision=sha))
        cfg = json.loads(Path(hf_hub_download(cand["id"], cand["onnx"].rsplit("/", 1)[0] + "/config.json",
                                              revision=sha)).read_text())
    else:
        onnx = target / "model.onnx"
        if not onnx.exists():
            from optimum.onnxruntime import ORTModelForSequenceClassification
            from transformers import AutoTokenizer
            ORTModelForSequenceClassification.from_pretrained(cand["id"], revision=sha, export=True).save_pretrained(target)
            AutoTokenizer.from_pretrained(cand["id"], revision=sha).save_pretrained(target)
        snapshot_download(cand["id"], revision=sha, allow_patterns=["config.json"])
        tok, cfg = target / "tokenizer.json", json.loads((target / "config.json").read_text())
    return onnx, tok, {"revision": sha, "id2label": cfg.get("id2label")}


def quantize(onnx: Path, work: Path, name: str) -> Path:
    from onnxruntime.quantization import QuantType, quantize_dynamic
    out = work / f"{name}.int8.onnx"
    if not out.exists():
        quantize_dynamic(str(onnx), str(out), weight_type=QuantType.QInt8)
    return out


class Classifier:
    def __init__(self, onnx: Path, tokenizer: Path, injection_index: int, threads: int) -> None:
        import onnxruntime as ort
        from tokenizers import Tokenizer
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        opts.inter_op_num_threads = 1
        self.session = ort.InferenceSession(str(onnx), opts, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}
        self.tok = Tokenizer.from_file(str(tokenizer))
        self.tok.no_truncation()
        self.tok.no_padding()
        self.cls = self.tok.token_to_id("[CLS]") if self.tok.token_to_id("[CLS]") is not None else self.tok.token_to_id("<s>")
        self.sep = self.tok.token_to_id("[SEP]") if self.tok.token_to_id("[SEP]") is not None else self.tok.token_to_id("</s>")
        self.idx = injection_index

    def score(self, text: str) -> float:
        # Windows built by hand (same as the engine): tokenizers' `overflowing` drops windows of long inputs.
        ids = self.tok.encode(text, add_special_tokens=False).ids
        body = MAX_LEN - 2
        starts = [0] if len(ids) <= body else list(range(0, len(ids) - STRIDE, body - STRIDE))
        best = 0.0
        for s in starts:
            w = [self.cls, *ids[s:s + body], self.sep]
            feed = {"input_ids": np.array([w], dtype=np.int64), "attention_mask": np.ones((1, len(w)), dtype=np.int64)}
            if "token_type_ids" in self.inputs:
                feed["token_type_ids"] = np.zeros_like(feed["input_ids"])
            logits = self.session.run(None, {k: v for k, v in feed.items() if k in self.inputs})[0][0]
            e = np.exp(logits - logits.max())
            best = max(best, float(e[self.idx] / e.sum()))
        return best


def auc(scores: list[float], labels: list[bool]) -> float:
    pos = [s for s, y in zip(scores, labels) if y]
    neg = [s for s, y in zip(scores, labels) if not y]
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def rates(scores: list[float], labels: list[bool], threshold: float) -> dict[str, float]:
    tp = sum(s >= threshold and y for s, y in zip(scores, labels))
    fp = sum(s >= threshold and not y for s, y in zip(scores, labels))
    p, n = sum(labels), len(labels) - sum(labels)
    return {"detection_rate": round(tp / p, 4), "false_positive_rate": round(fp / n, 4), "tp": tp, "fp": fp,
            "positives": p, "negatives": n}


def injection_index(id2label: dict[str, str] | None) -> int:
    for k, v in (id2label or {}).items():
        if str(v).upper() in ("INJECTION", "LABEL_1", "1", "JAILBREAK"):
            return int(k)
    return 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--work", type=Path, default=Path("/tmp/injection-candidates"))
    ap.add_argument("--latency-sample", type=int, default=150)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--models", default="", help="comma-separated subset of candidate ids (default: all)")
    args = ap.parse_args()
    chosen = {m for m in args.models.split(",") if m}
    args.work.mkdir(parents=True, exist_ok=True)
    data = {}
    for name, (file, field, is_attack) in DATASETS.items():
        rows = json.loads((args.data / file).read_text(encoding="utf8"))
        data[name] = ([r[field] for r in rows], [bool(is_attack(r)) for r in rows])
    results = []
    for cand in CANDIDATES:
        if chosen and cand["id"] not in chosen:
            continue
        onnx, tok, meta = prepare(cand, args.work)
        idx = injection_index(meta["id2label"])
        variants = {"fp32": onnx, "int8": quantize(onnx, args.work, cand["id"].replace("/", "__"))}
        for variant, path in variants.items():
            base = rss_mib()
            clf = Classifier(path, tok, idx, threads=4)
            loaded = rss_mib()
            entry: dict[str, Any] = {"model": cand["id"], "variant": variant, "revision": meta["revision"],
                                     "licence": cand["licence"], "trained_on": cand["trained_on"],
                                     "file_mib": round(path.stat().st_size / 2**20, 1),
                                     "rss_after_load_mib": round(loaded - base, 1), "splits": {}}
            for name, (texts, labels) in data.items():
                scores = [clf.score(t) for t in texts]
                entry["splits"][name] = {"contaminated": name in cand["trained_on"], "auc": round(auc(scores, labels), 4),
                                         "at_0.5": rates(scores, labels, 0.5),
                                         "scores": [round(s, 5) for s in scores]}
            single = Classifier(path, tok, idx, threads=1)
            sample = [t for texts, _ in data.values() for t in texts[: args.latency_sample]]
            lat = []
            for t in sample:
                t0 = time.perf_counter()
                single.score(t)
                lat.append((time.perf_counter() - t0) * 1000)
            q = statistics.quantiles(lat, n=100)
            entry["latency_ms_1thread"] = {"p50": round(q[49], 1), "p95": round(q[94], 1), "n": len(lat)}
            entry["peak_rss_mib"] = round(rss_mib(), 1)
            results.append(entry)
            print(json.dumps({k: v for k, v in entry.items() if k != "splits"}),
                  {n: {k: v for k, v in s.items() if k != "scores"} for n, s in entry["splits"].items()}, flush=True)
            del clf, single
    report = {"labels": {name: data[name][1] for name in data}, "candidates": results}
    if args.out:
        args.out.write_text(json.dumps(report))


if __name__ == "__main__":
    main()
