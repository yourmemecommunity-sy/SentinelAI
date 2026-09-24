"""Every failure mode must BLOCK with failed_closed=true and never return the input text."""
import io
import json
import logging

from app.config.settings import Settings
from app.detectors.base import Detector
from app.detectors.registry import DetectorRegistry, default_registry
from app.models import Action, ScanRequest
from app.pipelines import ScanPipeline
from conftest import fake_aws_key


class ExplodingDetector(Detector):
    name = "exploding"

    def detect(self, text):
        raise RuntimeError(f"boom: {text}")  # message contains the text: must not be logged or returned


class SlowDetector(Detector):
    name = "slow"

    def detect(self, text):
        import time
        time.sleep(0.05)
        return []


def req(text="hello", **kw):
    return ScanRequest(text=text, organization_id="org", **kw)


def assert_fail_closed(res, reason_prefix):
    assert res.decision is Action.BLOCK and res.failed_closed
    assert res.sanitized_text is None
    assert res.fail_closed_reason.startswith(reason_prefix), res.fail_closed_reason
    assert res.risk.risk_score == 100


def test_detector_exception_blocks():
    reg = default_registry()
    reg.register(ExplodingDetector())
    res = ScanPipeline(reg).scan(req("some secret text"))
    assert_fail_closed(res, "detector_error:exploding")
    assert "some secret text" not in res.model_dump_json()


def test_empty_registry_blocks_and_is_not_ready():
    p = ScanPipeline(DetectorRegistry())
    assert not p.is_ready()
    assert_fail_closed(p.scan(req()), "no_detectors_registered")


def test_oversized_input_blocks():
    p = ScanPipeline(default_registry(), Settings(max_input_chars=100))
    assert_fail_closed(p.scan(req("x" * 101)), "input_too_large")
    assert not p.scan(req("x" * 100)).failed_closed


def test_time_budget_exceeded_blocks():
    reg = DetectorRegistry([SlowDetector(), SlowDetector()])
    p = ScanPipeline(reg, Settings(time_budget_ms=60))
    assert_fail_closed(p.scan(req()), "timeout")


def test_unexpected_internal_error_blocks(monkeypatch):
    p = ScanPipeline(default_registry())
    monkeypatch.setattr("app.pipelines.scan_pipeline.assess", lambda *a, **k: 1 / 0)
    assert_fail_closed(p.scan(req("hi")), "internal_error:ZeroDivisionError")


def test_policy_evaluation_error_blocks(monkeypatch):
    p = ScanPipeline(default_registry())
    monkeypatch.setattr("app.pipelines.scan_pipeline.evaluate", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    assert_fail_closed(p.scan(req("a@example.com")), "policy_error:ValueError")


def test_sanitization_verification_failure_blocks(monkeypatch):
    p = ScanPipeline(default_registry())
    from app.sanitization import SanitizeResult
    from app.models import EntityType
    # A sanitizer bug that leaves the value in place must be caught by the post-sanitization rescan.
    monkeypatch.setattr("app.pipelines.scan_pipeline.sanitize",
                        lambda text, resolved, vault: SanitizeResult(text, {(EntityType.EMAIL, Action.MASK): 1}))
    assert_fail_closed(p.scan(req("mail me at a@example.com")), "sanitization_verification_failed")


def test_never_logs_scanned_content():
    stream = io.StringIO()
    logger = logging.getLogger("sentinel.security_engine")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger("sentinel.security_engine").handlers[0].formatter
                         if logger.handlers else logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    try:
        secret = fake_aws_key()
        res = ScanPipeline(default_registry()).scan(req(f"key {secret} and mail user@example.com"))
    finally:
        logger.removeHandler(handler)
    logged = stream.getvalue()
    assert "scan_completed" in logged
    assert secret not in logged and "user@example.com" not in logged
    assert secret not in res.model_dump_json()
    for line in logged.splitlines():
        json.loads(line)  # structured
