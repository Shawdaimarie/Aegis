"""Typed contracts for zero-trust agent identity and delegated authorization."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_CONTEXT_VALUE_LENGTH = 256

Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,127}$")]
TenantId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")]
Audience = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,127}$")]
Action = Annotated[str, Field(pattern=r"^[a-z][a-z0-9._:-]{1,95}$")]
Resource = Annotated[str, Field(min_length=3, max_length=256)]
ContextKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")]


class PrincipalKind(StrEnum):
    """Closed principal classes supported by the reference control plane."""

    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class DecisionReason(StrEnum):
    """Stable reason codes emitted by every authorization decision."""

    ALLOW = "allow"
    INVALID_TOKEN = "invalid_token"  # noqa: S105 - public decision code, not a credential
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    ACTION_DENIED = "action_denied"
    RESOURCE_DENIED = "resource_denied"
    CONTEXT_MISMATCH = "context_mismatch"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    USE_BUDGET_EXHAUSTED = "use_budget_exhausted"
    REPLAY_DETECTED = "replay_detected"
    STATE_UNAVAILABLE = "state_unavailable"


class Principal(BaseModel):
    """A human, AI agent, or service identity inside one tenant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Identifier
    kind: PrincipalKind
    tenant: TenantId


class CapabilityGrant(BaseModel):
    """Canonical, signed authority delegated to exactly one subject."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(default="aegis.capability.v1", pattern=r"^aegis\.capability\.v1$")
    capability_id: Identifier
    key_id: Identifier
    issuer: Principal
    subject: Principal
    tenant: TenantId
    audience: Audience
    actions: tuple[Action, ...]
    resources: tuple[Resource, ...]
    issued_at: int = Field(ge=0)
    not_before: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    max_uses: int = Field(ge=1, le=10_000)
    requires_approval: bool = False
    context_constraints: dict[ContextKey, str] = Field(default_factory=dict)
    parent_capability_id: Identifier | None = None
    delegation_depth: int = Field(ge=0, le=8, default=0)

    @field_validator("actions", "resources")
    @classmethod
    def _normalize_unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize nonempty scope values before signing."""
        normalized = tuple(sorted(set(values)))
        if not normalized:
            raise ValueError("at least one value is required")
        return normalized

    @field_validator("resources")
    @classmethod
    def _validate_resource_patterns(cls, resources: tuple[str, ...]) -> tuple[str, ...]:
        """Reject ambiguous wildcards outside the terminal subtree form."""
        for resource in resources:
            if "*" in resource and not resource.endswith("/**"):
                raise ValueError("resource wildcards are allowed only as a terminal '/**'")
            if resource.count("*") not in {0, 2}:
                raise ValueError("resource wildcards must use exactly '/**'")
        return resources

    @field_validator("context_constraints")
    @classmethod
    def _validate_context_values(cls, values: dict[str, str]) -> dict[str, str]:
        """Bound each context value and canonicalize key ordering."""
        for key, value in values.items():
            if not value or len(value) > MAX_CONTEXT_VALUE_LENGTH:
                raise ValueError(f"context constraint {key!r} must contain 1-256 characters")
        return dict(sorted(values.items()))

    @model_validator(mode="after")
    def _validate_scope(self) -> CapabilityGrant:
        """Require tenant, time and delegation metadata to be internally consistent."""
        if self.issuer.tenant != self.tenant or self.subject.tenant != self.tenant:
            raise ValueError("issuer, subject, and capability must share one tenant")
        if self.not_before < self.issued_at:
            raise ValueError("not_before cannot precede issued_at")
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must be later than not_before")
        if self.delegation_depth == 0 and self.parent_capability_id is not None:
            raise ValueError("root capability cannot declare a parent")
        if self.delegation_depth > 0 and self.parent_capability_id is None:
            raise ValueError("delegated capability requires a parent id")
        return self


class IssuedCapability(BaseModel):
    """Signed token and its decoded, non-secret grant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str
    grant: CapabilityGrant


class IssueCapabilityRequest(BaseModel):
    """Administrative request to issue a root capability."""

    model_config = ConfigDict(extra="forbid")

    issuer: Principal
    subject: Principal
    audience: Audience
    actions: tuple[Action, ...]
    resources: tuple[Resource, ...]
    ttl_seconds: int = Field(ge=30, le=86_400)
    not_before_seconds: int = Field(ge=0, le=3_600, default=0)
    max_uses: int = Field(ge=1, le=10_000, default=1)
    requires_approval: bool = False
    context_constraints: dict[ContextKey, str] = Field(default_factory=dict)


class DelegateCapabilityRequest(BaseModel):
    """Request a strictly narrower child capability."""

    model_config = ConfigDict(extra="forbid")

    parent_token: str = Field(min_length=32)
    delegated_by: Principal
    subject: Principal
    actions: tuple[Action, ...]
    resources: tuple[Resource, ...]
    ttl_seconds: int = Field(ge=30, le=86_400)
    max_uses: int = Field(ge=1, le=10_000, default=1)
    requires_approval: bool = False
    context_constraints: dict[ContextKey, str] = Field(default_factory=dict)


class AuthorizationIntent(BaseModel):
    """The exact operation an approval or authorization decision binds to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor: Principal
    tenant: TenantId
    audience: Audience
    action: Action
    resource: Resource
    context: dict[ContextKey, str] = Field(default_factory=dict)


class AuthorizationRequest(AuthorizationIntent):
    """Authorization request carrying a signed capability and replay identifier."""

    token: str = Field(min_length=32)
    request_id: Identifier
    approval_id: Identifier | None = None


class ApprovalRequest(BaseModel):
    """Request a one- or few-use human approval bound to one intent."""

    model_config = ConfigDict(extra="forbid")

    capability_token: str = Field(min_length=32)
    approver: Principal
    intent: AuthorizationIntent
    ttl_seconds: int = Field(ge=15, le=3_600, default=300)
    max_uses: int = Field(ge=1, le=100, default=1)

    @model_validator(mode="after")
    def _human_approval_only(self) -> ApprovalRequest:
        """Validate the declared identity shape; authentication belongs to the API boundary."""
        if self.approver.kind is not PrincipalKind.HUMAN:
            raise ValueError("approvals must be issued by a human principal")
        if self.approver.tenant != self.intent.tenant:
            raise ValueError("approver and intent must share one tenant")
        return self


class ApprovalGrant(BaseModel):
    """Stored human authorization for one exact operation fingerprint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: Identifier
    capability_id: Identifier
    tenant: TenantId
    approver: Principal
    intent_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    max_uses: int = Field(ge=1, le=100)


class RevokeCapabilityRequest(BaseModel):
    """Administrative revocation request."""

    model_config = ConfigDict(extra="forbid")

    capability_id: Identifier
    revoked_by: Principal
    reason: str = Field(min_length=3, max_length=256)


class InspectCapabilityRequest(BaseModel):
    """Decode a capability after validating its signature."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32)


class AuthorizationDecision(BaseModel):
    """Stable, auditable result of one authorization check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: Identifier
    request_id: Identifier
    allowed: bool
    reason: DecisionReason
    evaluated_at: int = Field(ge=0)
    capability_id: Identifier | None = None
    subject: Principal | None = None
    remaining_uses: int | None = Field(default=None, ge=0)
