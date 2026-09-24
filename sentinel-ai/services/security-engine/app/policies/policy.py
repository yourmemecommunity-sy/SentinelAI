"""Policy schema. Wire format is snake_case; mirrored in packages/shared-types/src/policy.ts.

Design decisions (see docs/architecture/adr/0003-policy-semantics.md):
  * Deny-overrides: if several rules match one detection, the most restrictive action wins.
  * Unmatched detections fall back to the severity-based baseline (never to ALLOW for CRITICAL/HIGH).
  * Live credentials, payment cards and threat signals can be sanitized or blocked but never ALLOWed;
    such rules are rejected at load time AND floored at evaluation time (defence in depth).
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.types import (
    NEVER_ALLOW_ENTITIES, THREAT_ENTITIES, Action, Direction, EntityType, Severity,
)

_HHMM = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


class TimeWindow(BaseModel):
    """UTC time-of-day window; `start` > `end` wraps past midnight. Non-UTC zones are not supported."""
    model_config = ConfigDict(extra="forbid")
    start: str
    end: str

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        if not _HHMM.match(v):
            raise ValueError("expected HH:MM (24h, UTC)")
        return v


class RuleScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    users: list[str] | None = None
    teams: list[str] | None = None
    applications: list[str] | None = None
    providers: list[str] | None = None
    models: list[str] | None = None
    environments: list[str] | None = None
    ip_cidrs: list[str] | None = None
    time_window_utc: TimeWindow | None = None
    directions: list[Direction] | None = None

    @field_validator("ip_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str] | None) -> list[str] | None:
        for c in v or []:
            ipaddress.ip_network(c, strict=False)  # raises ValueError -> 422 (request rejected, fail closed)
        return v


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity: EntityType
    action: Action
    severity: Severity | None = None  # optional severity floor used for risk scoring
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    scope: RuleScope | None = None

    @model_validator(mode="after")
    def _no_unsafe_allow(self) -> "PolicyRule":
        if self.action is Action.ALLOW and (
            self.entity in NEVER_ALLOW_ENTITIES or self.entity in THREAT_ENTITIES
            or self.severity is Severity.CRITICAL
        ):
            raise ValueError(f"{self.entity.value} cannot be ALLOWed by policy (sanitize or block instead)")
        return self


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(min_length=1, max_length=128)
    organization_id: str | None = Field(default=None, max_length=128)
    version: int = Field(default=1, ge=1)
    rules: list[PolicyRule] = Field(default_factory=list, max_length=500)
