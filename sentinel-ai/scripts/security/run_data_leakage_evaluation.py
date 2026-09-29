#!/usr/bin/env python3
"""Independent evaluation of the PII and secrets detectors on PUBLIC, labelled datasets the rules were never tuned on.

The engine's own evaluation set (run_evaluation.py) is self-authored. This script measures how the same detectors do on
data written by other people, with no tuning: the engine is exactly the committed code.

  pii      ai4privacy/pii-masking-400k and ai4privacy/pii-masking-300k, English VALIDATION (held-out) split, fetched at a
           pinned Hub revision. Every labelled span is scored.
  secrets  Samsung/CredData (Apache-2.0): ~68k candidate credential lines from ~300 public repositories, each labelled
           True/False by humans, with a category. The corpus is rebuilt by CredData's own `download_data.py` (Linux),
           which obfuscates the real secret values. No split exists and nothing was tuned on it, so all of it is held out.

Scoring
  PII     A labelled span is DETECTED if the engine reports the corresponding entity type overlapping it (e.g. EMAIL for
          an email span), and CAUGHT if any detection of any type overlaps it. Per engine entity type, the
          false-positive rate is the share of its detections that overlap no labelled span at all (the datasets do not
          label everything, so this is an upper bound). Labels with no corresponding detector (names, usernames, IP
          addresses...) are reported separately as uncovered.
  Secrets A candidate line is FLAGGED if the engine reports any credential-type entity on it. Detection rate = flagged
          True lines / True lines; false-positive rate = flagged False lines / False lines, per CredData category.
          CredData's False lines are hard negatives (things other scanners flagged), not random text.

Privacy: no dataset text or secret value is ever printed or written; only counts. AI4Privacy data is licensed for
non-commercial research use only, so it is cached outside the repository and never redistributed.

Usage (from sentinel-ai/, with the security engine's dependencies installed):
    python scripts/security/run_data_leakage_evaluation.py --suite pii [--limit N] [--report out.json]
    python scripts/security/run_data_leakage_evaluation.py --suite pii --split train --sample 6000   # tuning ONLY

The default split is the held-out VALIDATION split, used only to measure. `--split train` scores the TRAIN split and is the
only split any detector change may be tuned on (see docs/verification/11-pii-improvement-cycle.md).
    python scripts/security/run_data_leakage_evaluation.py --suite secrets --creddata /path/to/CredData [--report out.json]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "services" / "security-engine"))
CACHE = Path.home() / ".cache" / "sentinelai-independent-eval"

# name -> (Hub revision, file in the repo, SHA-256 of that file). The revision pins the content; the hash double-checks it.
PII_SOURCES: dict[str, tuple[str, str, str | None]] = {
    "ai4privacy/pii-masking-400k": ("414d0a3b5798a152588a0828f1c08a5787de10f4", "data/validation/1en.jsonl",
                                    "e77bf977fd8a8b722ff859abd46bf7d20fb46b596cc139e55df32ebee88fcb39"),
    "ai4privacy/pii-masking-300k": ("c8c77895a005822682b66ab547fc0422579bc1d3", "data/validation/1english_openpii_8k.jsonl",
                                    "3112f54972d1a117936b75fa455e41872df36d4a8e7500ac9663e3ee671729e1"),
}
# Same datasets and revisions, English TRAIN files: the only data detector changes may be tuned on.
PII_TRAIN_SOURCES: dict[str, tuple[str, str, str | None]] = {
    "ai4privacy/pii-masking-400k": ("414d0a3b5798a152588a0828f1c08a5787de10f4", "data/train/1en.jsonl", None),
    "ai4privacy/pii-masking-300k": ("c8c77895a005822682b66ab547fc0422579bc1d3", "data/train/1english_openpii_30k.jsonl", None),
}

# Dataset label -> engine entity types that count as "the right detector" for it.
LABEL_TO_ENTITY: dict[str, set[str]] = {
    # NER layer (added in the 2026-09-28 improvement cycle; before it these labels had no detector)
    "GIVENNAME": {"NAME"}, "GIVENNAME1": {"NAME"}, "GIVENNAME2": {"NAME"}, "SURNAME": {"NAME"},
    "LASTNAME1": {"NAME"}, "LASTNAME2": {"NAME"}, "LASTNAME3": {"NAME"},
    "CITY": {"LOCATION"}, "STATE": {"LOCATION"}, "COUNTRY": {"LOCATION"},
    "EMAIL": {"EMAIL"},
    "TELEPHONENUM": {"PHONE"}, "TEL": {"PHONE"},
    "SOCIALNUM": {"SSN"}, "SOCIALNUMBER": {"SSN"},
    "PASSPORT": {"PASSPORT"},
    "DRIVERLICENSENUM": {"DRIVER_LICENSE"}, "DRIVERLICENSE": {"DRIVER_LICENSE"},
    "DATEOFBIRTH": {"DATE_OF_BIRTH"}, "BOD": {"DATE_OF_BIRTH"},
    "CREDITCARDNUMBER": {"CREDIT_CARD"},
    "ACCOUNTNUM": {"BANK_ACCOUNT"},
    "PASSWORD": {"PASSWORD"}, "PASS": {"PASSWORD"},
    "STREET": {"ADDRESS"}, "BUILDINGNUM": {"ADDRESS"}, "BUILDING": {"ADDRESS"}, "ZIPCODE": {"ADDRESS"},
    "POSTCODE": {"ADDRESS"}, "SECADDRESS": {"ADDRESS"},
}
# Labels the engine has no detector for at all (no generic national-ID / tax-ID detector outside India; usernames, IPs...).
UNCOVERED = {"USERNAME", "IP", "TIME", "DATE", "SEX", "TITLE", "GEOCOORD", "CARDISSUER", "IDCARDNUM", "IDCARD", "TAXNUM"}

SECRET_ENTITIES = {"API_KEY", "AWS_CREDENTIAL", "GOOGLE_CREDENTIAL", "GITHUB_TOKEN", "JWT", "OAUTH_TOKEN", "PASSWORD",
                   "PRIVATE_KEY", "CONNECTION_STRING", "HIGH_ENTROPY_SECRET"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_pii(name: str, sources: dict[str, tuple[str, str, str | None]] | None = None) -> tuple[Path, dict[str, Any]]:
    rev, path, pinned = (sources or PII_SOURCES)[name]
    local = CACHE / f"{name.replace('/', '__')}__{rev[:8]}__{Path(path).name}"
    if not local.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/datasets/{name}/resolve/{rev}/{path}"
        with urllib.request.urlopen(url, timeout=600) as r, open(local, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
    digest = sha256_file(local)
    return local, {"revision": rev, "file": path, "sha256": digest, "pinned_sha256": pinned,
                   "matches_pin": None if pinned is None else digest == pinned}


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def rate(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def eval_pii(pipeline: Any, limit: int | None, split: str = "validation", sample: int | None = None) -> dict[str, Any]:
    from app.models import Direction, ScanRequest

    out: dict[str, Any] = {}
    sources = PII_TRAIN_SOURCES if split == "train" else PII_SOURCES
    for name in sources:
        path, integrity = fetch_pii(name, sources)
        integrity["split"] = split
        keep: set[int] | None = None
        if sample is not None:  # a fixed, seeded random sample of line numbers (reproducible)
            import random
            with open(path, encoding="utf8") as f:
                total = sum(1 for _ in f)
            keep = set(random.Random(20260928).sample(range(total), min(sample, total)))
        span_n: Counter[str] = Counter()
        span_detected: Counter[str] = Counter()
        span_caught: Counter[str] = Counter()
        det_total: Counter[str] = Counter()
        det_right: Counter[str] = Counter()
        det_other_label: Counter[str] = Counter()
        det_unlabelled: Counter[str] = Counter()
        records = decisions_protected = records_with_pii = 0
        failed_closed: Counter[str] = Counter()
        started = time.perf_counter()
        with open(path, encoding="utf8") as f:
            for line_no, line in enumerate(f):
                if limit is not None and records >= limit:
                    break
                if keep is not None and line_no not in keep:
                    continue
                row = json.loads(line)
                text = row["source_text"]
                gold = row["privacy_mask"]
                gold = json.loads(gold) if isinstance(gold, str) else gold
                res = pipeline.scan(ScanRequest(text=text, organization_id="independent-eval", direction=Direction.INPUT))
                dets = [(d.entity.value, d.location.start, d.location.end) for d in res.detections]
                records += 1
                if res.failed_closed:
                    failed_closed[str(res.fail_closed_reason)] += 1
                if gold:
                    records_with_pii += 1
                    decisions_protected += res.decision.value != "ALLOW"
                for g in gold:
                    lab = g["label"]
                    span_n[lab] += 1
                    want = LABEL_TO_ENTITY.get(lab, set())
                    hit = [e for e, s, en in dets if overlaps(s, en, g["start"], g["end"])]
                    span_caught[lab] += bool(hit)
                    span_detected[lab] += any(e in want for e in hit)
                for e, s, en in dets:
                    det_total[e] += 1
                    over = [g for g in gold if overlaps(s, en, g["start"], g["end"])]
                    if not over:
                        det_unlabelled[e] += 1
                    elif any(e in LABEL_TO_ENTITY.get(g["label"], set()) for g in over):
                        det_right[e] += 1
                    else:
                        det_other_label[e] += 1
        per_label = {}
        for lab in sorted(span_n, key=lambda k: -span_n[k]):
            per_label[lab] = {
                "spans": span_n[lab],
                "engine_type": "/".join(sorted(LABEL_TO_ENTITY[lab])) if lab in LABEL_TO_ENTITY else None,
                "covered": lab in LABEL_TO_ENTITY,
                "detection_rate": rate(span_detected[lab], span_n[lab]) if lab in LABEL_TO_ENTITY else None,
                "caught_by_any_detector": rate(span_caught[lab], span_n[lab]),
            }
        per_entity = {e: {"detections": det_total[e], "on_matching_label": det_right[e], "on_other_label": det_other_label[e],
                          "on_unlabelled_text": det_unlabelled[e], "false_positive_rate": rate(det_unlabelled[e], det_total[e])}
                      for e in sorted(det_total, key=lambda k: -det_total[k])}
        out[name] = {"integrity": integrity, "records": records, "seconds": round(time.perf_counter() - started, 1),
                     "records_with_pii_not_allowed": rate(decisions_protected, records_with_pii),
                     "failed_closed": dict(failed_closed),
                     "per_label": per_label, "per_engine_entity": per_entity}
    return out


def eval_secrets(pipeline: Any, root: Path, limit: int | None) -> dict[str, Any]:
    from app.models import Direction, ScanRequest

    if not (root / "meta").is_dir() or not (root / "data").is_dir():
        raise SystemExit(f"{root} is not a CredData checkout with generated data/ (run its download_data.py first)")
    rows: list[dict[str, str]] = []
    for meta in sorted((root / "meta").glob("*.csv")):
        with open(meta, encoding="utf8", newline="") as f:
            rows.extend(csv.DictReader(f))
    by_cat: dict[str, Counter[str]] = defaultdict(Counter)
    overall: Counter[str] = Counter()
    missing = 0
    cache: dict[str, list[str]] = {}
    started = time.perf_counter()
    for i, r in enumerate(rows):
        if limit is not None and i >= limit:
            break
        fp = root / r["FilePath"]
        if str(fp) not in cache:
            try:
                cache.clear() if len(cache) > 256 else None
                cache[str(fp)] = fp.read_text(encoding="utf8", errors="replace").splitlines()
            except OSError:
                missing += 1
                continue
        lines = cache[str(fp)]
        a, b = int(r["LineStart"]), int(r["LineEnd"])
        if not 1 <= a <= b <= len(lines):
            missing += 1
            continue
        text = "\n".join(lines[a - 1:b])[:20000]
        if not text.strip():
            missing += 1
            continue
        truth = r["GroundTruth"].strip().upper() == "T"
        res = pipeline.scan(ScanRequest(text=text, organization_id="independent-eval", direction=Direction.INPUT))
        flagged = any(d.entity.value in SECRET_ENTITIES for d in res.detections)
        key = "true" if truth else "false"
        cats = [c.strip() for c in (r.get("Category") or "Other").split(":") if c.strip()] or ["Other"]
        for bucket in [overall] + [by_cat[c] for c in cats]:
            bucket[key] += 1
            bucket[f"{key}_flagged"] += flagged
    def summarise(c: Counter[str]) -> dict[str, Any]:
        return {"true_lines": c["true"], "detection_rate": rate(c["true_flagged"], c["true"]),
                "false_lines": c["false"], "false_positive_rate": rate(c["false_flagged"], c["false"])}
    commit = None
    head = root / ".git" / "HEAD"
    if head.exists():
        ref = head.read_text().strip()
        commit = (root / ".git" / ref[5:]).read_text().strip() if ref.startswith("ref: ") and (root / ".git" / ref[5:]).exists() else ref
    return {"Samsung/CredData": {"commit": commit, "meta_rows": len(rows), "unreadable_rows_skipped": missing,
                                 "seconds": round(time.perf_counter() - started, 1), "overall": summarise(overall),
                                 "per_category": {k: summarise(v) for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1]["true"])}}}


def print_report(rep: dict[str, Any]) -> None:
    for name, r in rep.get("pii", {}).items():
        i = r["integrity"]
        print(f"\n== {name}  (English {i.get('split', 'validation')} split, {r['records']} records, {r['seconds']} s)")
        print(f"   revision {i['revision'][:8]}, {i['file']}, sha256 {i['sha256'][:16]}... "
              f"({'not pinned' if i['pinned_sha256'] is None else ('matches pin' if i['matches_pin'] else 'DOES NOT MATCH PIN')})")
        print(f"   records containing labelled PII whose decision was not ALLOW: {r['records_with_pii_not_allowed']:.1%}")
        print(f"   scans that failed closed (blocked with no detections, e.g. time budget): {sum(r['failed_closed'].values())} "
              f"{r['failed_closed'] or ''}")
        print(f"   {'label':18} {'spans':>6}  {'engine type':15} {'detection':>9}  {'caught by any':>13}")
        for lab, m in r["per_label"].items():
            det = f"{m['detection_rate']:.1%}" if m["covered"] else "no detector"
            print(f"   {lab:18} {m['spans']:>6}  {m['engine_type'] or '-':15} {det:>9}  {m['caught_by_any_detector']:>13.1%}")
        print(f"   {'engine entity':18} {'detections':>10} {'on right label':>15} {'on other label':>15} {'unlabelled':>11} {'FP rate':>8}")
        for e, m in r["per_engine_entity"].items():
            print(f"   {e:18} {m['detections']:>10} {m['on_matching_label']:>15} {m['on_other_label']:>15} {m['on_unlabelled_text']:>11} "
                  f"{m['false_positive_rate']:>8.1%}")
    for name, r in rep.get("secrets", {}).items():
        o = r["overall"]
        print(f"\n== {name}  (commit {str(r['commit'])[:8]}, {r['meta_rows']} labelled lines, {r['unreadable_rows_skipped']} unreadable skipped, {r['seconds']} s)")
        print(f"   OVERALL  true lines {o['true_lines']}: detection {o['detection_rate']:.1%}   false lines {o['false_lines']}: false-positive rate {o['false_positive_rate']:.1%}")
        print(f"   {'category':34} {'true':>6} {'detection':>9} {'false':>7} {'FP rate':>8}")
        for c, m in r["per_category"].items():
            dr = "-" if m["detection_rate"] is None else f"{m['detection_rate']:.1%}"
            fr = "-" if m["false_positive_rate"] is None else f"{m['false_positive_rate']:.1%}"
            print(f"   {c[:34]:34} {m['true_lines']:>6} {dr:>9} {m['false_lines']:>7} {fr:>8}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", choices=("pii", "secrets", "all"), default="pii")
    ap.add_argument("--creddata", type=Path, help="path to a Samsung/CredData checkout after download_data.py")
    ap.add_argument("--limit", type=int, help="score only the first N records per dataset (smoke test)")
    ap.add_argument("--split", choices=("validation", "train"), default="validation",
                    help="validation = held-out measurement (default); train = the only split used for tuning")
    ap.add_argument("--sample", type=int, help="score a fixed seeded random sample of N records per dataset")
    ap.add_argument("--report", help="write the full JSON report here")
    args = ap.parse_args(argv)

    logging.disable(logging.INFO)  # the engine logs one INFO line per scan
    from app.pipelines import default_pipeline

    pipeline = default_pipeline()
    rep: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tuned_on_these_datasets": False}
    if args.suite in ("pii", "all"):
        rep["pii"] = eval_pii(pipeline, args.limit, args.split, args.sample)
    if args.suite in ("secrets", "all"):
        if not args.creddata:
            raise SystemExit("--creddata is required for the secrets suite")
        rep["secrets"] = eval_secrets(pipeline, args.creddata, args.limit)
    print_report(rep)
    if args.report:
        Path(args.report).write_text(json.dumps(rep, indent=2), encoding="utf8")
        print(f"\nreport written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
