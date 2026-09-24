#!/usr/bin/env python3
"""Independent evaluation: run the real security engine over PUBLIC, third-party prompt-injection / jailbreak datasets.

SentinelAI's own evaluation set (run_evaluation.py) is self-authored, so it proves the rules do what they were written to do,
not how they fare on attacks written by someone else. This script measures that, with no tuning: the engine's rules were
never adjusted on these datasets, and the headline numbers use each dataset's held-out TEST split.

Datasets (both Apache-2.0 on the Hugging Face Hub), fetched through the Hub's datasets-server JSON API:
  * deepset/prompt-injections          text, label (1 = injection, 0 = benign)          - English and German
  * jackhhao/jailbreak-classification  prompt, type ("jailbreak" / "benign")            - English

They are cached OUTSIDE the repository (the repository's datasets/ directory is synthetic-only by policy) and pinned by a
SHA-256 of their canonical content: if a dataset changes upstream the report says so loudly.

Two ways of counting a prompt as "flagged" are reported, because they answer different questions:
  * threat-detected - the engine found a PROMPT_INJECTION / JAILBREAK / SYSTEM_PROMPT_EXTRACTION / DATA_EXFILTRATION entity
  * blocked         - the engine's decision was BLOCK (for any reason, e.g. a credential in a benign prompt)

Usage (one command, from the repository root, with the security engine's dependencies installed):
    python scripts/security/run_independent_evaluation.py [--report out.json] [--split test|all] [--offline]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "services" / "security-engine"))

CACHE = Path.home() / ".cache" / "sentinelai-independent-eval"
API = "https://datasets-server.huggingface.co/rows"

# text field, how to turn the raw label into "attack" / "benign", and the pinned content hash per split (None = not pinned).
DATASETS: dict[str, dict[str, Any]] = {
    "deepset/prompt-injections": {
        "text": "text", "attack": lambda row: row["label"] == 1, "splits": ("train", "test"),
        # Content hashes of the rows fetched on 2026-09-26 (Hub revision 4f61ecb0).
        "pinned": {"test": "1c104ff9d288c52c27ef8d21fdc2b630c720baaab391170a89c859fe96961a47",
                   "train": "af388005540d6fac6e796a34e2699c7e7bd86d29213d496a0406655c6532cb74"},
    },
    "jackhhao/jailbreak-classification": {
        "text": "prompt", "attack": lambda row: row["type"] == "jailbreak", "splits": ("train", "test"),
        # Content hashes of the rows fetched on 2026-09-26 (Hub revision 2f2ceeb3).
        "pinned": {"test": "cbef1d3202fbd476ef87dc1d46166759c856d0e892584f8afe68dd3696624213",
                   "train": "53648974f89caa8ce2f3b6c15cb6bcf6b32ae23c3054241ac0f2e0fd568c0002"},
    },
}

# Words common in German and rare in English ("die", "was", "an" etc. are excluded: they are English words too). Only used to
# split the results by language; it is a heuristic and labelled as such in the report.
GERMAN = re.compile(r"\b(und|nicht|ist|ich|der|das|eine|einen|für|auf|mit|wie|sie|wir|sind|bitte|vergiss|ignoriere|alle|oder|auch|über)\b", re.I)


def fetch(dataset: str, split: str, offline: bool) -> list[dict[str, Any]]:
    path = CACHE / f"{dataset.replace('/', '__')}__{split}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf8"))
    if offline:
        raise SystemExit(f"{dataset}/{split} is not cached and --offline was given")
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        q = urllib.parse.urlencode({"dataset": dataset, "config": "default", "split": split, "offset": offset, "length": 100})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(f"{API}?{q}", timeout=60) as r:
                    page = json.load(r)
                break
            except OSError:
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        rows.extend(item["row"] for item in page["rows"])
        offset += len(page["rows"])
        if not page["rows"] or offset >= page["num_rows_total"]:
            break
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf8")
    return rows


def content_hash(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def rates(c: Counter[str]) -> dict[str, Any]:
    atk, ben = c["attack"], c["benign"]
    out: dict[str, Any] = {"attacks": atk, "benign": ben}
    for how in ("threat", "blocked"):
        tp, fp = c[f"attack_{how}"], c[f"benign_{how}"]
        out[how] = {
            "detection_rate": round(tp / atk, 4) if atk else None,
            "false_positive_rate": round(fp / ben, 4) if ben else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "tp": tp, "fn": atk - tp, "fp": fp, "tn": ben - fp,
        }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", help="write the full JSON report here")
    ap.add_argument("--split", choices=("test", "all"), default="test", help="test = held-out test splits only (headline)")
    ap.add_argument("--offline", action="store_true", help="use the cache only")
    args = ap.parse_args(argv)

    logging.disable(logging.INFO)  # the engine logs one INFO line per scan; keep the report readable
    from app.models import Direction, ScanRequest
    from app.models.types import THREAT_ENTITIES, Action
    from app.pipelines import default_pipeline

    pipeline = default_pipeline()
    report: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "split": args.split,
                              "tuned_on_these_datasets": False, "datasets": {}}
    for name, spec in DATASETS.items():
        splits = ("test",) if args.split == "test" else spec["splits"]
        per_cat: dict[str, Counter[str]] = defaultdict(Counter)
        overall: Counter[str] = Counter()
        entities: Counter[str] = Counter()
        integrity: dict[str, Any] = {}
        misses: list[str] = []
        fps: list[str] = []
        for split in splits:
            rows = fetch(name, split, args.offline)
            digest = content_hash(rows)
            pinned = spec["pinned"].get(split)
            integrity[split] = {"rows": len(rows), "sha256": digest,
                                "pinned": pinned, "matches_pin": None if pinned is None else digest == pinned}
            for row in rows:
                text = str(row[spec["text"]])
                attack = bool(spec["attack"](row))
                res = pipeline.scan(ScanRequest(text=text, organization_id="independent-eval", direction=Direction.INPUT))
                threat = any(d.entity in THREAT_ENTITIES for d in res.detections)
                blocked = res.decision == Action.BLOCK
                for d in res.detections:
                    entities[d.entity.value] += 1
                kind = "attack" if attack else "benign"
                lang = "German (heuristic)" if len({w.lower() for w in GERMAN.findall(text)}) >= 3 else "English/other (heuristic)"
                for bucket in (overall, per_cat[f"{kind} / {lang}"]):
                    bucket[kind] += 1
                    bucket[f"{kind}_threat"] += threat
                    bucket[f"{kind}_blocked"] += blocked
                if attack and not threat and len(misses) < 8:
                    misses.append(text[:140])
                if not attack and threat and len(fps) < 8:
                    fps.append(text[:140])
        report["datasets"][name] = {
            "integrity": integrity, "overall": rates(overall),
            "per_category": {k: rates(v) for k, v in sorted(per_cat.items())},
            "entities_detected": dict(entities.most_common()),
            "sample_missed_attacks": misses, "sample_false_positives": fps,
        }

    for name, r in report["datasets"].items():
        o = r["overall"]
        print(f"\n== {name}  (split: {args.split}; attacks={o['attacks']} benign={o['benign']})")
        for split, i in r["integrity"].items():
            pin = "not pinned" if i["pinned"] is None else ("matches pin" if i["matches_pin"] else "DOES NOT MATCH PIN - dataset changed upstream")
            print(f"   {split}: {i['rows']} rows, sha256 {i['sha256'][:16]}... ({pin})")
        for how, label in (("threat", "threat detected"), ("blocked", "blocked")):
            m = o[how]
            print(f"   {label:16} detection rate {m['detection_rate']:.1%}  false-positive rate "
                  f"{(m['false_positive_rate'] or 0):.1%}  precision {(m['precision'] or 0):.1%}  (TP {m['tp']} FN {m['fn']} FP {m['fp']} TN {m['tn']})")
        for cat, m in r["per_category"].items():
            n = m["attacks"] or m["benign"]
            flagged = m["threat"]["tp"] + m["threat"]["fp"]
            print(f"     {cat:42} n={n:4}  threat-flagged {flagged:4} ({flagged / n:.1%})")
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf8")
        print(f"\nreport written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
