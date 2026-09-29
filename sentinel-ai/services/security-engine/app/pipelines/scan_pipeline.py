"""Scan pipeline: detectors -> policy -> sanitize -> verify -> risk -> decision.

FAIL-CLOSED: any failure to reach a safe decision (oversize input, detector error, timeout, policy
error, sanitization that cannot be verified, unexpected exception) yields decision BLOCK with
`failed_closed=true` and a machine-readable reason. Nothing here ever returns the original text on error.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Iterable

from app.config.settings import DETECTOR_BUNDLE_VERSION, Settings
from app.detectors.registry import DetectorRegistry, default_registry
from app.models.scan import EntityAction, ScanRequest, ScanResult
from app.models.types import CONTEXTUAL_ENTITIES, Action, Detection, EntityType, Risk, RiskFactor, RiskLevel
from app.policies import BASELINE_POLICY_ID, Policy, evaluate
from app.policies.evaluator import ResolvedDetection
from app.risk import assess
from app.sanitization import InMemoryTokenVault, NullVault, RemoteTokenVault, TokenVault, VaultUnavailableError, sanitize
from app.utils.logging import get_logger, log_event

_log = get_logger()
_BASELINE = Policy(policy_id=BASELINE_POLICY_ID)


class FailClosed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ScanPipeline:
    def __init__(self, registry: DetectorRegistry | None = None, settings: Settings | None = None) -> None:
        # `is None`, not `or`: an explicitly empty registry must stay empty (and then fail closed).
        self.settings = settings if settings is not None else Settings()
        self.registry = registry if registry is not None else default_registry(self.settings)

    # -- readiness: a pipeline with no detectors must not receive traffic
    def is_ready(self) -> bool:
        # Every registered detector must be usable (e.g. the NER model loaded): one that is not would fail every scan.
        return len(self.registry) > 0 and all(d.healthy() for d in self.registry.detectors)

    def self_test(self) -> bool:
        """Canary for /ready: a known-bad synthetic input must be blocked by detection (not by an error)."""
        canary = "aws key " + "AK" + "IA" + "ABCDEFGHIJKLMNOP"  # assembled at runtime; not a real credential
        try:
            res = self._scan(ScanRequest(text=canary, organization_id="canary"), "canary", time.perf_counter(), None)
        except Exception:  # noqa: BLE001
            return False
        if not (res.decision is Action.BLOCK and any(d.entity.value == "AWS_CREDENTIAL" for d in res.detections)):
            return False
        if any(d.name == "ner" for d in self.registry.detectors):
            # NER canary: a synthetic name must be found, so a model that loads but does not work is not "ready".
            try:
                ner = self._scan(ScanRequest(text="Please forward the file to Maria Gonzalez in Berlin.", organization_id="canary"),
                                 "canary", time.perf_counter(), None)
            except Exception:  # noqa: BLE001
                return False
            return any(d.entity.value == "NAME" for d in ner.detections)
        return True

    def scan(self, req: ScanRequest, vault: TokenVault | None = None) -> ScanResult:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        if vault is None and req.vault_session:
            vault = self._session_vault(req)
        try:
            result = self._scan(req, request_id, started, vault)
        except FailClosed as fc:
            result = self._fail_closed(req, request_id, started, fc.reason)
        except Exception as exc:  # noqa: BLE001 - deliberately broad: unknown failure must block
            result = self._fail_closed(req, request_id, started, f"internal_error:{type(exc).__name__}")
        log_event(_log, "scan_completed", request_id=request_id, organization_id=req.organization_id,
                  direction=req.direction.value, decision=result.decision.value,
                  failed_closed=result.failed_closed, reason=result.fail_closed_reason,
                  risk_level=result.risk.risk_level.value, policy_id=result.policy_id,
                  entity_types=sorted({d.entity.value for d in result.detections}),
                  latency_ms=result.latency_ms)
        return result

    # ------------------------------------------------------------------
    def _budget_ms(self, chars: int) -> float:
        """Time budget for one request: a base plus an allowance per 1,000 characters (NER cost grows with length)."""
        return self.settings.time_budget_ms + self.settings.time_budget_per_kchar_ms * chars / 1000

    def _budget(self, started: float, budget_ms: float) -> None:
        if (time.perf_counter() - started) * 1000 > budget_ms:
            raise FailClosed("timeout")

    def _detect(self, text: str, started: float, budget_ms: float) -> list[Detection]:
        found: dict[tuple[str, int, int], Detection] = {}
        for detector in self.registry.detectors:
            self._budget(started, budget_ms)
            try:
                dets = detector.detect(text)
            except Exception as exc:  # noqa: BLE001
                raise FailClosed(f"detector_error:{detector.name}:{type(exc).__name__}") from exc
            for d in dets:
                key = (d.entity.value, d.location.start, d.location.end)
                if key not in found or found[key].confidence < d.confidence:
                    found[key] = d
        self._budget(started, budget_ms)
        return sorted(found.values(), key=lambda d: (d.location.start, d.location.end, d.entity.value))

    def _session_vault(self, req: ScanRequest) -> TokenVault:
        s = self.settings
        if not s.vault_url:
            return NullVault()
        return RemoteTokenVault(s.vault_url, s.vault_token, req.organization_id, req.vault_session or "", s.vault_timeout_s)

    def _scan(self, req: ScanRequest, request_id: str, started: float, vault: TokenVault | None) -> ScanResult:
        if len(req.text) > self.settings.max_input_chars:
            raise FailClosed("input_too_large")
        if len(self.registry) == 0:
            raise FailClosed("no_detectors_registered")
        unhealthy = [d.name for d in self.registry.detectors if not d.healthy()]
        if unhealthy:  # e.g. the NER model failed to load: refuse rather than scan with a detector missing
            raise FailClosed(f"detector_unavailable:{','.join(unhealthy)}")

        policy = req.policy or _BASELINE
        budget_ms = self._budget_ms(len(req.text))
        detections = self._detect(req.text, started, budget_ms)

        try:
            resolved = evaluate(detections, policy, req.context, req.direction)
        except Exception as exc:  # noqa: BLE001
            raise FailClosed(f"policy_error:{type(exc).__name__}") from exc

        policy_decision = max((r.action for r in resolved), key=lambda a: a.rank, default=Action.ALLOW)
        risk = assess(resolved, policy_decision, req.context, req.direction)
        decision = risk.decision

        sanitized: str | None = None
        entity_actions: list[EntityAction] = []
        if not decision.withholds_content:
            # If risk escalated to BLOCK we already withheld above; otherwise sanitize per resolved actions.
            vault = vault if vault is not None else InMemoryTokenVault()
            try:
                result = sanitize(req.text, resolved, vault)
            except VaultUnavailableError as exc:
                # The policy asked for tokens the vault could not provide: an outage must not silently become a different action.
                raise FailClosed("vault_unavailable") from exc
            sanitized = result.text
            entity_actions = [EntityAction(entity=e, action=a, count=n) for (e, a), n in sorted(
                result.applied.items(), key=lambda kv: (kv[0][0].value, kv[0][1].value))]
            if result.applied:
                sanitized_values = {(r.detection.entity, req.text[r.detection.location.start:r.detection.location.end].casefold())
                                    for r in resolved if r.action.sanitizes and r.detection.entity in CONTEXTUAL_ENTITIES}
                self._verify_clean(sanitized, {r.detection.entity for r in resolved if r.action.sanitizes}, sanitized_values,
                                   started, budget_ms)
        else:
            entity_actions = self._withheld_actions(resolved, decision)

        return ScanResult(
            request_id=request_id, decision=decision, failed_closed=False, fail_closed_reason=None,
            detections=detections, entity_actions=entity_actions, risk=risk, sanitized_text=sanitized,
            policy_id=policy.policy_id, detector_version=DETECTOR_BUNDLE_VERSION,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def _verify_clean(self, sanitized: str, sanitized_entities: set[EntityType],
                      sanitized_values: set[tuple[EntityType, str]], started: float, budget_ms: float) -> None:
        """Re-scan sanitized text and fail closed if something we claimed to sanitize is still there.

        Deterministic (rule-based) types: any residual detection of a sanitized type fails. Contextual (NER) types: the
        model may tag *different* words once the text has changed, which is a first-pass miss, not a masking failure;
        what must never happen is a sanitized VALUE surviving, so for those types the residual value is compared."""
        for d in self._detect(sanitized, started, budget_ms):
            if d.entity not in sanitized_entities:
                continue
            if d.entity not in CONTEXTUAL_ENTITIES:
                raise FailClosed("sanitization_verification_failed")
            if (d.entity, sanitized[d.location.start:d.location.end].casefold()) in sanitized_values:
                raise FailClosed("sanitization_verification_failed")

    @staticmethod
    def _withheld_actions(resolved: Iterable[ResolvedDetection], decision: Action) -> list[EntityAction]:
        counts: dict[tuple[EntityType, Action], int] = {}
        for r in resolved:
            act = r.action if r.action.withholds_content else decision
            counts[(r.detection.entity, act)] = counts.get((r.detection.entity, act), 0) + 1
        return [EntityAction(entity=e, action=a, count=n) for (e, a), n in sorted(
            counts.items(), key=lambda kv: (kv[0][0].value, kv[0][1].value))]

    def _fail_closed(self, req: ScanRequest, request_id: str, started: float, reason: str) -> ScanResult:
        return ScanResult(
            request_id=request_id, decision=Action.BLOCK, failed_closed=True, fail_closed_reason=reason,
            detections=[], entity_actions=[],
            risk=Risk(risk_score=100, risk_level=RiskLevel.CRITICAL, decision=Action.BLOCK,
                      factors=[RiskFactor(name="fail_closed", contribution=100.0, detail=reason)]),
            sanitized_text=None, policy_id=(req.policy.policy_id if req.policy else BASELINE_POLICY_ID),
            detector_version=DETECTOR_BUNDLE_VERSION,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )


def default_pipeline(settings: Settings | None = None) -> ScanPipeline:
    s = settings or Settings()
    return ScanPipeline(default_registry(s), s)
