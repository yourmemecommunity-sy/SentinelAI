from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class StageSummary:
    decision: str
    risk_level: str
    event_id: str


@dataclass(frozen=True)
class Security:
    input: StageSummary
    output: StageSummary


@dataclass(frozen=True)
class SecureResponse:
    """A response that passed input AND output security. `content` is the (possibly sanitized) model output."""

    content: str
    provider: str
    model: str
    security: Security
    #: Present when a session was used: "applied" (tokens restored) or "degraded" (vault unavailable, tokens left as-is).
    hydration: Optional[str] = None


@dataclass(frozen=True)
class Detection:
    entity: str
    confidence: float
    severity: str
    start: int
    end: int
    detector: str


@dataclass(frozen=True)
class RiskFactor:
    name: str
    contribution: float
    detail: str


@dataclass(frozen=True)
class ScanResult:
    request_id: str
    event_id: Optional[str]
    decision: str
    #: True for BLOCK / QUARANTINE: `sanitized_text` is None and the text must not be forwarded anywhere.
    blocked: bool
    failed_closed: bool
    fail_closed_reason: Optional[str]
    risk_score: int
    risk_level: str
    policy_id: str
    #: Text safe to send to a model, or None when blocked.
    sanitized_text: Optional[str]
    detections: List[Detection] = field(default_factory=list)
    risk_factors: List[RiskFactor] = field(default_factory=list)


@dataclass(frozen=True)
class FileFinding:
    type: str
    severity: str
    detail: str


@dataclass(frozen=True)
class FileInfo:
    sha256: str
    size: int
    detected_type: Optional[str]
    mime: Optional[str]
    pages: Optional[int]
    ocr_used: bool


@dataclass(frozen=True)
class FileScanResult:
    event_id: Optional[str]
    decision: str
    #: True for BLOCK/QUARANTINE (including fail-closed): do NOT forward the file or any of its content anywhere.
    blocked: bool
    failed_closed: bool
    #: Why it was blocked (e.g. "macros_present", "malware_detected", "scanner_unreachable"), when applicable.
    reason: Optional[str]
    file: FileInfo
    risk_score: int
    risk_level: str
    policy_id: str
    #: The file extracted text with your policy applied - safe to give to a model. None when blocked.
    sanitized_text: Optional[str]
    findings: List[FileFinding] = field(default_factory=list)
    detections: List[Detection] = field(default_factory=list)


@dataclass(frozen=True)
class StreamSummary:
    """Set on a SecureStream once it has ended with the gateway's `done` event."""

    provider: str
    model: str
    hydration: str
    security: Security


@dataclass(frozen=True)
class CheckResult:
    allowed: bool
    decision: str
    risk_level: str
    failed_closed: bool
    event_id: Optional[str]
