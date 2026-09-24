#!/usr/bin/env python3
"""SentinelAI Security Evaluation Lab runner.

Runs every dataset record through the real scan pipeline and reports detection rate, false
positive/negative rates, precision, recall, policy accuracy and latency. Exit code 1 (CI failure) if:
  * any record marked `critical` does not produce exactly its expected action (target: 100%), or
  * the false-positive rate on benign records exceeds --max-fp-rate, or
  * dataset integrity checks fail (schema violation, non-synthetic source, manifest hash mismatch).

Usage: python scripts/security/run_evaluation.py [--report report.json] [--max-fp-rate 0.02]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DATASETS = REPO / "datasets"
sys.path.insert(0, str(REPO / "services" / "security-engine"))
sys.path.insert(0, str(REPO / "scripts" / "dataset"))
from defang import materialize, raw_secret_findings  # noqa: E402  (secret-type values are stored defanged)

REQUIRED = {"id", "category", "subcategory", "text", "entities", "severity", "expected_action", "source", "version"}
ACTIONS = {"ALLOW", "HASH", "MASK", "TOKENIZE", "REDACT", "QUARANTINE", "BLOCK"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_records() -> tuple[list[dict], list[str]]:
    records, problems, seen = [], [], set()
    manifest = json.loads((DATASETS / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = DATASETS / entry["file"]
        raw = path.read_bytes().decode("utf-8")
        if hashlib.sha256(raw.encode("utf-8")).hexdigest() != entry["sha256"]:
            problems.append(f"manifest hash mismatch (dataset changed without regeneration): {entry['file']}")
        for n, line in enumerate(raw.splitlines(), 1):
            rec = json.loads(line)
            where = f"{entry['file']}:{n}"
            if missing := REQUIRED - rec.keys():
                problems.append(f"{where} missing fields {sorted(missing)}")
                continue
            if rec["id"] in seen:
                problems.append(f"{where} duplicate id {rec['id']}")
            seen.add(rec["id"])
            if not (rec["source"] == "synthetic" or rec["source"].startswith("licensed:")):
                problems.append(f"{where} source must be 'synthetic' or 'licensed:<name>', got {rec['source']!r}")
            if rec["expected_action"] not in ACTIONS or rec["severity"] not in SEVERITIES:
                problems.append(f"{where} invalid action/severity")
            # A credential-shaped string stored verbatim is a dataset defect (see scripts/dataset/defang.py).
            if found := raw_secret_findings(rec["text"]):
                problems.append(f"{where} secret-shaped value stored verbatim ({', '.join(found)}); regenerate the datasets")
            rec["text"] = materialize(rec["text"])     # the realistic text the engine is graded on
            for e in rec["entities"]:
                if not (0 <= e["start"] < e["end"] <= len(rec["text"])):
                    problems.append(f"{where} entity offsets out of range")
            records.append(rec)
    return records, problems


def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def evaluate(records: list[dict]) -> dict:
    from app.models import Direction, ScanRequest
    from app.pipelines import default_pipeline

    pipeline = default_pipeline()
    per_cat: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    latencies, failures = [], []
    tp = fp = fn = tn = 0  # binary: "should be sanitized/blocked" vs result
    for rec in records:
        req = ScanRequest(text=rec["text"], organization_id="eval-org", direction=Direction(rec.get("direction", "INPUT")))
        res = pipeline.scan(req)
        latencies.append(res.latency_ms)
        expected, got = rec["expected_action"], res.decision.value

        found = [(d.entity.value, d.location.start, d.location.end) for d in res.detections]
        entities_ok = all(any(t == e["type"] and overlaps(s, en, e["start"], e["end"]) for t, s, en in found)
                          for e in rec["entities"] if e["type"] != "ID")
        action_ok = expected == got
        passed = action_ok and entities_ok and not res.failed_closed

        c = per_cat[rec["category"]]
        c["n"] += 1
        c["passed"] += passed
        c["action_ok"] += action_ok
        c["entities_ok"] += entities_ok
        c["critical_n"] += bool(rec.get("critical"))
        c["critical_failed"] += bool(rec.get("critical")) and not passed

        should, did = expected != "ALLOW", got != "ALLOW"
        tp += should and did
        fn += should and not did
        fp += (not should) and did
        tn += (not should) and not did
        if not passed:
            failures.append({"id": rec["id"], "category": rec["category"], "critical": bool(rec.get("critical")),
                             "expected": expected, "got": got, "entities_ok": entities_ok,
                             "failed_closed": res.failed_closed, "detected": sorted({f[0] for f in found})})

    lat = sorted(latencies)
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]  # noqa: E731
    return {
        "records": len(records),
        "categories": {k: dict(v) for k, v in sorted(per_cat.items())},
        "metrics": {
            "detection_rate": round(tp / (tp + fn), 4) if tp + fn else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "false_negative_rate": round(fn / (tp + fn), 4) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
            "policy_accuracy": round(sum(v["action_ok"] for v in per_cat.values()) / len(records), 4),
            "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "max": lat[-1], "mean": round(statistics.mean(lat), 3)},
        },
        "critical": {"total": sum(v["critical_n"] for v in per_cat.values()),
                     "failed": sum(v["critical_failed"] for v in per_cat.values())},
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", help="write full JSON report to this path")
    ap.add_argument("--max-fp-rate", type=float, default=0.02)
    ap.add_argument("--critical-only", action="store_true", help="accepted for CI readability; gating is always on critical cases")
    args = ap.parse_args(argv)

    records, problems = load_records()
    report = evaluate(records)
    report["dataset_problems"] = problems
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    m = report["metrics"]
    print(f"records={report['records']}  critical={report['critical']['total']}  critical_failed={report['critical']['failed']}")
    print(f"detection/recall={m['recall']}  precision={m['precision']}  FN-rate={m['false_negative_rate']}  "
          f"FP-rate={m['false_positive_rate']}  policy-accuracy={m['policy_accuracy']}")
    print(f"latency ms: {m['latency_ms']}")
    for cat, v in report["categories"].items():
        print(f"  {cat:<20} {v['passed']}/{v['n']} passed")
    for f in report["failures"][:25]:
        print(f"  FAIL {f}")
    for p in problems:
        print(f"  DATASET PROBLEM: {p}")

    ok = (report["critical"]["failed"] == 0 and not problems
          and (m["false_positive_rate"] or 0.0) <= args.max_fp_rate)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
