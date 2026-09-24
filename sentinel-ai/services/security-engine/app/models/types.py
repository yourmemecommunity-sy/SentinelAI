"""Domain and wire types for the security engine.

Wire format is snake_case JSON and is mirrored in packages/shared-types/src/security.ts.
Detections NEVER carry the matched value - only location and a salted digest.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class Action(str, Enum):
    ALLOW = "ALLOW"
    HASH = "HASH"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        """Restrictiveness order; deny-overrides conflict resolution uses the maximum."""
        return _ACTION_RANK[self]

    @property
    def withholds_content(self) -> bool:
        return self in (Action.BLOCK, Action.QUARANTINE)

    @property
    def sanitizes(self) -> bool:
        return self in (Action.MASK, Action.REDACT, Action.TOKENIZE, Action.HASH)


_ACTION_RANK = {a: i for i, a in enumerate(
    [Action.ALLOW, Action.HASH, Action.MASK, Action.TOKENIZE, Action.REDACT, Action.QUARANTINE, Action.BLOCK])}


class Direction(str, Enum):
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EntityType(str, Enum):
    # PII
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PAN = "PAN"
    AADHAAR = "AADHAAR"
    PASSPORT = "PASSPORT"
    SSN = "SSN"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    # Financial
    CREDIT_CARD = "CREDIT_CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    UPI = "UPI"
    IFSC = "IFSC"
    # Secrets / credentials
    API_KEY = "API_KEY"
    AWS_CREDENTIAL = "AWS_CREDENTIAL"
    GOOGLE_CREDENTIAL = "GOOGLE_CREDENTIAL"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    JWT = "JWT"
    OAUTH_TOKEN = "OAUTH_TOKEN"
    PASSWORD = "PASSWORD"
    PRIVATE_KEY = "PRIVATE_KEY"
    CONNECTION_STRING = "CONNECTION_STRING"
    HIGH_ENTROPY_SECRET = "HIGH_ENTROPY_SECRET"
    # Business data
    INTERNAL_URL = "INTERNAL_URL"
    CONFIDENTIAL_MARKER = "CONFIDENTIAL_MARKER"
    CUSTOM_CONFIDENTIAL = "CUSTOM_CONFIDENTIAL"
    # Threats
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    JAILBREAK = "JAILBREAK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


THREAT_ENTITIES = frozenset({
    EntityType.PROMPT_INJECTION, EntityType.SYSTEM_PROMPT_EXTRACTION,
    EntityType.JAILBREAK, EntityType.DATA_EXFILTRATION,
})

# Live credentials / payment data: policy may sanitize them but can never ALLOW them.
NEVER_ALLOW_ENTITIES = frozenset({
    EntityType.PRIVATE_KEY, EntityType.AWS_CREDENTIAL, EntityType.GOOGLE_CREDENTIAL,
    EntityType.GITHUB_TOKEN, EntityType.JWT, EntityType.OAUTH_TOKEN, EntityType.PASSWORD,
    EntityType.CONNECTION_STRING, EntityType.API_KEY, EntityType.CREDIT_CARD,
})


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)
    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> "Location":
        if self.end < self.start:
            raise ValueError("end must be >= start")
        return self


class Detection(BaseModel):
    """Structured evidence. Contains no matched text; `value_digest` is a keyed HMAC prefix."""
    model_config = ConfigDict(frozen=True)
    entity: EntityType
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    location: Location
    detector: str
    detector_version: str
    value_digest: str | None = None


class RequestContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str | None = Field(default=None, max_length=256)
    team: str | None = Field(default=None, max_length=256)
    application: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, max_length=64)
    ip: str | None = Field(default=None, max_length=64)


class RiskFactor(BaseModel):
    name: str
    contribution: float
    detail: str


class Risk(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    decision: Action
    factors: list[RiskFactor]
