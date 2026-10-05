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
        decisions: Counter[str] = Counter()   # decision per record
        decided_by: Counter[str] = Counter()  # which tier decided (explanation), so cascade-added blocks are visible
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
                decisions[res.decision.value] += 1
                if res.explanation is not None:
                    decided_by[res.explanation.decided_by] += 1
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
                     "failed_closed": dict(failed_closed), "decisions": dict(decisions), "decided_by": dict(decided_by),
                     "per_label": per_label, "per_engine_entity": per_entity}
    return out


def creddata_rows(root: Path) -> list[dict[str, str]]:
    if not (root / "meta").is_dir() or not (root / "data").is_dir():
        raise SystemExit(f"{root} is not a CredData checkout with generated data/ (run its download_data.py first)")
    rows: list[dict[str, str]] = []
    for meta in sorted((root / "meta").glob("*.csv")):
        with open(meta, encoding="utf8", newline="") as f:
            rows.extend(csv.DictReader(f))
    return rows


def shard_range(n: int, shard: tuple[int, int] | None) -> tuple[int, int]:
    """Contiguous slice [lo, hi) of the n rows for shard k of N (contiguous keeps the per-file line cache effective)."""
    if shard is None:
        return 0, n
    k, total = shard
    return n * k // total, n * (k + 1) // total


def _fmt_s(s: float) -> str:
    s = int(s)
    return f"{s // 3600}h{s % 3600 // 60:02d}m{s % 60:02d}s"


def _save_state(path: Path, state: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state), encoding="utf8")
    tmp.replace(path)  # atomic: a crash mid-write leaves the previous checkpoint intact


def eval_secrets_state(pipeline: Any, root: Path, limit: int | None, *, shard: tuple[int, int] | None = None,
                       checkpoint: Path | None = None, progress_every: int = 1000, fingerprint: str = "") -> dict[str, Any]:
    """Scores CredData rows and returns the raw counters. With `checkpoint`, the counters are saved every
    `progress_every` rows and a restarted run resumes after the last saved row (the row order is deterministic)."""
    from app.models import Direction, ScanRequest

    rows = creddata_rows(root)
    lo, hi = shard_range(len(rows), shard)
    if limit is not None:
        hi = min(hi, lo + limit)
    state: dict[str, Any] = {"fingerprint": fingerprint, "meta_rows": len(rows), "lo": lo, "hi": hi, "next": lo,
                             "elapsed": 0.0, "missing": 0, "overall": {}, "by_cat": {}, "decisions": {},
                             "decided_by": {}, "failed_closed": {}}
    if checkpoint is not None and checkpoint.exists():
        saved = json.loads(checkpoint.read_text(encoding="utf8"))
        if (saved.get("fingerprint"), saved.get("meta_rows"), saved.get("lo"), saved.get("hi")) != (fingerprint, len(rows), lo, hi):
            raise SystemExit(f"{checkpoint} was written by a different engine/configuration; move it away to start over")
        state = saved
        print(f"resuming from checkpoint: row {state['next'] - lo}/{hi - lo} of this run, "
              f"{_fmt_s(state['elapsed'])} already spent", flush=True)
    overall: Counter[str] = Counter(state["overall"])
    by_cat: dict[str, Counter[str]] = defaultdict(Counter, {k: Counter(v) for k, v in state["by_cat"].items()})
    decisions: Counter[str] = Counter(state["decisions"])      # "<truth>:<decision>", e.g. "false:BLOCK"
    decided_by: Counter[str] = Counter(state["decided_by"])    # "<truth>:<tier that decided>"
    failed_closed: Counter[str] = Counter(state["failed_closed"])
    missing = int(state["missing"])
    cache: dict[str, list[str]] = {}
    started, before = time.perf_counter(), float(state["elapsed"])
    start_row = int(state["next"])

    def snapshot(next_row: int) -> dict[str, Any]:
        return {**state, "next": next_row, "elapsed": before + time.perf_counter() - started, "missing": missing,
                "overall": dict(overall), "by_cat": {k: dict(v) for k, v in by_cat.items()},
                "decisions": dict(decisions), "decided_by": dict(decided_by), "failed_closed": dict(failed_closed)}

    for i in range(start_row, hi):
        r = rows[i]
        done = i + 1 - lo
        fp = root / r["FilePath"]
        text = None
        if str(fp) not in cache:
            try:
                cache.clear() if len(cache) > 256 else None
                cache[str(fp)] = fp.read_text(encoding="utf8", errors="replace").splitlines()
            except OSError:
                cache[str(fp)] = []
        lines = cache[str(fp)]
        a, b = int(r["LineStart"]), int(r["LineEnd"])
        if lines and 1 <= a <= b <= len(lines):
            text = "\n".join(lines[a - 1:b])[:20000]
        if not text or not text.strip():
            missing += 1
        else:
            truth = r["GroundTruth"].strip().upper() == "T"
            res = pipeline.scan(ScanRequest(text=text, organization_id="independent-eval", direction=Direction.INPUT))
            flagged = any(d.entity.value in SECRET_ENTITIES for d in res.detections)
            key = "true" if truth else "false"
            cats = [c.strip() for c in (r.get("Category") or "Other").split(":") if c.strip()] or ["Other"]
            for bucket in [overall] + [by_cat[c] for c in cats]:
                bucket[key] += 1
                bucket[f"{key}_flagged"] += flagged
            overall[f"{key}_blocked"] += res.decision.value == "BLOCK"
            decisions[f"{key}:{res.decision.value}"] += 1
            if res.explanation is not None:
                decided_by[f"{key}:{res.explanation.decided_by}"] += 1
            if res.failed_closed:
                failed_closed[str(res.fail_closed_reason)] += 1
        if progress_every and (done % progress_every == 0 or i + 1 == hi):
            snap = snapshot(i + 1)
            if checkpoint is not None:
                _save_state(checkpoint, snap)
            run_s = time.perf_counter() - started
            scored_now = i + 1 - start_row
            eta = run_s / scored_now * (hi - i - 1) if scored_now else 0.0
            print(f"progress {done}/{hi - lo} lines ({done / (hi - lo):.1%})  elapsed {_fmt_s(snap['elapsed'])}  "
                  f"rate {scored_now / run_s if run_s else 0:.1f} lines/s  est. left {_fmt_s(eta)}  "
                  f"est. finish {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(time.time() + eta))}", flush=True)
    return snapshot(hi)


def merge_states(states: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"meta_rows": states[0]["meta_rows"], "elapsed": max(s["elapsed"] for s in states),
                           "cpu_seconds": sum(s["elapsed"] for s in states), "missing": sum(s["missing"] for s in states),
                           "shards": len(states)}
    for key in ("overall", "decisions", "decided_by", "failed_closed"):
        c: Counter[str] = Counter()
        for s in states:
            c.update(s[key])
        out[key] = dict(c)
    cats: dict[str, Counter[str]] = defaultdict(Counter)
    for s in states:
        for k, v in s["by_cat"].items():
            cats[k].update(v)
    out["by_cat"] = {k: dict(v) for k, v in cats.items()}
    return out


def secrets_report(root: Path, state: dict[str, Any]) -> dict[str, Any]:
    def summarise(c: dict[str, int]) -> dict[str, Any]:
        return {"true_lines": c.get("true", 0), "detection_rate": rate(c.get("true_flagged", 0), c.get("true", 0)),
                "false_lines": c.get("false", 0), "false_positive_rate": rate(c.get("false_flagged", 0), c.get("false", 0))}
    commit = None
    head = root / ".git" / "HEAD"
    if head.exists():
        ref = head.read_text().strip()
        commit = (root / ".git" / ref[5:]).read_text().strip() if ref.startswith("ref: ") and (root / ".git" / ref[5:]).exists() else ref
    o = state["overall"]
    overall = summarise(o)
    # BLOCK for any reason (a secret, a fail-closed scan, or a cascade injection verdict): what a caller would see.
    overall["true_blocked_rate"] = rate(o.get("true_blocked", 0), o.get("true", 0))
    overall["false_blocked_rate"] = rate(o.get("false_blocked", 0), o.get("false", 0))
    return {"Samsung/CredData": {"commit": commit, "meta_rows": state["meta_rows"], "unreadable_rows_skipped": state["missing"],
                                 "seconds": round(state["elapsed"], 1), "shards": state.get("shards", 1),
                                 "overall": overall, "decisions": state["decisions"], "decided_by": state["decided_by"],
                                 "failed_closed": state["failed_closed"],
                                 "per_category": {k: summarise(v) for k, v in sorted(state["by_cat"].items(),
                                                                                     key=lambda kv: -kv[1].get("true", 0))}}}


def eval_secrets(pipeline: Any, root: Path, limit: int | None) -> dict[str, Any]:
    return secrets_report(root, eval_secrets_state(pipeline, root, limit, progress_every=0))


def print_report(rep: dict[str, Any]) -> None:
    for name, r in rep.get("pii", {}).items():
        i = r["integrity"]
        print(f"\n== {name}  (English {i.get('split', 'validation')} split, {r['records']} records, {r['seconds']} s)")
        print(f"   revision {i['revision'][:8]}, {i['file']}, sha256 {i['sha256'][:16]}... "
              f"({'not pinned' if i['pinned_sha256'] is None else ('matches pin' if i['matches_pin'] else 'DOES NOT MATCH PIN')})")
        print(f"   records containing labelled PII whose decision was not ALLOW: {r['records_with_pii_not_allowed']:.1%}")
        print(f"   scans that failed closed (blocked with no detections, e.g. time budget): {sum(r['failed_closed'].values())} "
              f"{r['failed_closed'] or ''}")
        print(f"   decisions: {r.get('decisions')}   decided by: {r.get('decided_by')}")
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
        if "false_blocked_rate" in o:
            print(f"   BLOCKED for any reason  true lines {o['true_blocked_rate']:.1%}   false lines {o['false_blocked_rate']:.1%}")
            print(f"   decided by: {r.get('decided_by')}   failed closed: {r.get('failed_closed')}")
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
    ap.add_argument("--checkpoint", type=Path,
                    help="secrets: save progress here every --progress-every lines and resume from it if it exists")
    ap.add_argument("--progress-every", type=int, default=1000, help="secrets: progress line + checkpoint interval")
    ap.add_argument("--shard", help="secrets: K/N scores only the K-th of N contiguous slices (parallel runs)")
    ap.add_argument("--merge", type=Path, nargs="+",
                    help="secrets: merge finished shard checkpoints into --report (no scanning)")
    args = ap.parse_args(argv)
    rep: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tuned_on_these_datasets": False}

    if args.merge:
        if not args.creddata:
            raise SystemExit("--creddata is required with --merge (for the dataset commit)")
        states = [json.loads(p.read_text(encoding="utf8")) for p in args.merge]
        if len({s["fingerprint"] for s in states}) != 1:
            raise SystemExit("the shard checkpoints come from different engines/configurations")
        if unfinished := [str(p) for p, s in zip(args.merge, states) if s["next"] != s["hi"]]:
            raise SystemExit(f"unfinished shards: {unfinished}")
        rep["engine"] = states[0]["fingerprint"]
        rep["secrets"] = secrets_report(args.creddata, merge_states(states))
    else:
        logging.disable(logging.INFO)  # the engine logs one INFO line per scan
        from app.config.settings import Settings
        from app.pipelines import default_pipeline
        from app.policies import BASELINE_POLICY_ID, Policy

        # SENTINEL_CASCADE=on measures the cascade (its classifier can only ADD blocks to these benign-for-injection records)
        pipeline = default_pipeline(Settings.from_env())
        rep["engine"] = json.dumps(pipeline.versions(Policy(policy_id=BASELINE_POLICY_ID)), sort_keys=True)
        if args.suite in ("pii", "all"):
            rep["pii"] = eval_pii(pipeline, args.limit, args.split, args.sample)
        if args.suite in ("secrets", "all"):
            if not args.creddata:
                raise SystemExit("--creddata is required for the secrets suite")
            shard = None
            if args.shard:
                k, n = (int(x) for x in args.shard.split("/"))
                if not 0 <= k < n:
                    raise SystemExit("--shard K/N needs 0 <= K < N")
                shard = (k, n)
            state = eval_secrets_state(pipeline, args.creddata, args.limit, shard=shard, checkpoint=args.checkpoint,
                                       progress_every=args.progress_every,
                                       fingerprint=f"{rep['engine']}|limit={args.limit}")
            if shard is not None:  # a shard's result is its checkpoint; --merge builds the report
                print(f"shard {args.shard} finished")
                return 0
            rep["secrets"] = secrets_report(args.creddata, state)
    print_report(rep)
    if args.report:
        Path(args.report).write_text(json.dumps(rep, indent=2), encoding="utf8")
        print(f"\nreport written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
