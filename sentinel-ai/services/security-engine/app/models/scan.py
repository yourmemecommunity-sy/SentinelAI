"""Scan request/response contracts (wire format: snake_case JSON; see docs/api/openapi.yaml)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.explanation import Explanation
from app.models.types import Action, Detection, Direction, EntityType, RequestContext, Risk
from app.policies.policy import Policy


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    direction: Direction = Direction.INPUT
    organization_id: str = Field(min_length=1, max_length=128)
    context: RequestContext = Field(default_factory=RequestContext)
    policy: Policy | None = None  # absent -> severity-based baseline policy
    # Names the token-vault session that TOKENIZE actions write to (so a reply can later be de-tokenized). Absent -> one-way,
    # per-request tokens that are never exposed. Never trusted for tenancy: the vault namespaces by organization_id as well.
    vault_session: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:@-]{1,128}$")


class EntityAction(BaseModel):
    entity: EntityType
    action: Action
    count: int


class ScanResult(BaseModel):
    request_id: str
    decision: Action
    failed_closed: bool
    fail_closed_reason: str | None = None
    detections: list[Detection]
    entity_actions: list[EntityAction]
    risk: Risk
    sanitized_text: str | None  # None whenever the decision withholds content (BLOCK / QUARANTINE)
    policy_id: str
    detector_version: str
    latency_ms: float
    explanation: Explanation | None = None  # why this decision was made (no content; see app.models.explanation)
