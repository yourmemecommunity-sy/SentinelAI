"""CI gate: the SentinelAI Security Evaluation Suite must pass 100% of critical cases.

Run from the repo root with the security-engine environment:
    services/security-engine/.venv/Scripts/python -m pytest tests/security tests/regression
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "services" / "security-engine"))
_spec = importlib.util.spec_from_file_location("run_evaluation", REPO / "scripts" / "security" / "run_evaluation.py")
run_evaluation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_evaluation)

REQUIRED_CATEGORIES = {"PII", "FINANCIAL", "SECRETS", "PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION",
                       "MALICIOUS_DOCUMENT", "OUTPUT_LEAKAGE", "BENIGN"}


@pytest.fixture(scope="module")
def report():
    records, problems = run_evaluation.load_records()
    rep = run_evaluation.evaluate(records)
    rep["dataset_problems"] = problems
    return rep


def test_dataset_integrity(report):
    assert report["dataset_problems"] == []


def test_all_required_categories_are_covered(report):
    assert REQUIRED_CATEGORIES <= set(report["categories"])


def test_zero_critical_failures(report):
    assert report["critical"]["failed"] == 0, [f for f in report["failures"] if f["critical"]][:10]


def test_false_positive_rate_within_budget(report):
    assert (report["metrics"]["false_positive_rate"] or 0.0) <= 0.02


def test_no_fail_closed_events_on_evaluation_inputs(report):
    assert not [f for f in report["failures"] if f["failed_closed"]]
