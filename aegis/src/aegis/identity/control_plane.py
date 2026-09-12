"""Zero-trust capability issuance, delegation, approval, and authorization."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from aegis.core.errors import IntegrityError
from aegis.core.hashing import content_id
from aegis.governance.audit import AuditLog
from aegis.identity.capability import (
    CapabilityCodec,
    request_resource_allowed,
    validate_monotonic_delegation,
)
from aegis.identity.models import (
    ApprovalGrant,
    ApprovalRequest,
    AuthorizationDecision,
    AuthorizationIntent,
    AuthorizationRequest,
    CapabilityGrant,
    DecisionReason,
    DelegateCapabilityRequest,
    IssueCapabilityRequest,
    IssuedCapability,
    RevokeCapabilityRequest,
)
from aegis.identity.state import AuthorizationState, ConsumeRequest

Clock = Callable[[], int]


def _system_clock() -> int:
    """Return the current Unix time used by capability validity checks."""
    return int(time.time())


def intent_fingerprint(intent: AuthorizationIntent) -> str:
    """Return a stable fingerprint for one exact authorization intent."""
    payload = {
        "actor": intent.actor.model_dump(mode="json"),
        "tenant": intent.tenant,
        "audience": intent.audience,
        "action": intent.action,
        "resource": intent.resource,
        "context": dict(sorted(intent.context.items())),
    }
    return content_id(payload)


class IdentityControlPlane:
    """Issue and enforce short-lived, least-privilege agent capabilities."""

    def __init__(
        self,
        codec: CapabilityCodec,
        audit: AuditLog,
        *,
        state: AuthorizationState | None = None,
        clock: Clock = _system_clock,
    ) -> None:
        """Bind signing, audit, state, and clock dependencies."""
        self._codec = codec
        self._audit = audit
        self._state = state or AuthorizationState()
        self._clock = clock

    def _id(self, prefix: str) -> str:
        """Create a fresh identifier in the requested record namespace."""
        return f"{prefix}-{secrets.token_urlsafe(12)}"

    def issue(self, request: IssueCapabilityRequest) -> IssuedCapability:
        """Issue a root capability after validating tenant authority boundaries."""
        if request.issuer.tenant != request.subject.tenant:
            raise ValueError("issuer and subject must share one tenant")
        now = self._clock()
        grant = CapabilityGrant(
            capability_id=self._id("cap"),
            key_id=self._codec.key_id,
            issuer=request.issuer,
            subject=request.subject,
            tenant=request.subject.tenant,
            audience=request.audience,
            actions=request.actions,
            resources=request.resources,
            issued_at=now,
            not_before=now + request.not_before_seconds,
            expires_at=now + request.ttl_seconds,
            max_uses=request.max_uses,
            requires_approval=request.requires_approval,
            context_constraints=request.context_constraints,
        )
        token = self._codec.encode(grant)
        self._audit.append(
            actor=request.issuer.id,
            action="identity:issue",
            resource=f"capability:{grant.capability_id}",
            decision="issued",
            detail={
                "subject": grant.subject.id,
                "tenant": grant.tenant,
                "audience": grant.audience,
                "expires_at": str(grant.expires_at),
            },
        )
        return IssuedCapability(token=token, grant=grant)

    def inspect(self, token: str) -> CapabilityGrant:
        """Verify and decode a capability without consuming it."""
        grant = self._codec.decode(token)
        self._audit.append(
            actor="identity-control-plane",
            action="identity:inspect",
            resource=f"capability:{grant.capability_id}",
            decision="valid",
        )
        return grant

    def delegate(self, request: DelegateCapabilityRequest) -> IssuedCapability:
        """Issue a strictly narrower child capability."""
        parent = self._codec.decode(request.parent_token)
        now = self._clock()
        if parent.subject != request.delegated_by:
            raise ValueError("only the current capability subject may delegate authority")
        if self._state.is_revoked(parent.capability_id):
            raise ValueError("revoked capability cannot be delegated")
        if now < parent.not_before or now >= parent.expires_at:
            raise ValueError("inactive capability cannot be delegated")
        if request.subject.tenant != parent.tenant:
            raise ValueError("delegated subject must remain in the parent tenant")
        child_expires_at = min(now + request.ttl_seconds, parent.expires_at)
        child_constraints = dict(request.context_constraints)
        child_requires_approval = request.requires_approval or parent.requires_approval
        child = CapabilityGrant(
            capability_id=self._id("cap"),
            key_id=self._codec.key_id,
            issuer=request.delegated_by,
            subject=request.subject,
            tenant=parent.tenant,
            audience=parent.audience,
            actions=request.actions,
            resources=request.resources,
            issued_at=now,
            not_before=max(now, parent.not_before),
            expires_at=child_expires_at,
            max_uses=request.max_uses,
            requires_approval=child_requires_approval,
            context_constraints=child_constraints,
            parent_capability_id=parent.capability_id,
            delegation_depth=parent.delegation_depth + 1,
        )
        validate_monotonic_delegation(parent, child)
        token = self._codec.encode(child)
        parent_remaining = self._state.register_delegation(
            parent_capability_id=parent.capability_id,
            child_capability_id=child.capability_id,
            reserved_uses=child.max_uses,
            parent_max_uses=parent.max_uses,
        )
        self._audit.append(
            actor=request.delegated_by.id,
            action="identity:delegate",
            resource=f"capability:{child.capability_id}",
            decision="issued",
            detail={
                "parent": parent.capability_id,
                "subject": child.subject.id,
                "depth": str(child.delegation_depth),
                "parent_remaining_uses": str(parent_remaining),
            },
        )
        return IssuedCapability(token=token, grant=child)

    def approve(self, request: ApprovalRequest) -> ApprovalGrant:
        """Create a human approval bound to one exact authorization intent."""
        grant = self._codec.decode(request.capability_token)
        now = self._clock()
        if self._state.is_revoked(grant.capability_id):
            raise ValueError("cannot approve a revoked capability")
        reason = self._static_reason(grant, request.intent, now)
        if reason is not DecisionReason.ALLOW:
            raise ValueError(f"cannot approve intent outside capability scope: {reason}")
        if request.approver.tenant != grant.tenant:
            raise ValueError("approver must belong to the capability tenant")
        if request.max_uses > grant.max_uses:
            raise ValueError("approval use budget exceeds capability use budget")
        approval = ApprovalGrant(
            approval_id=self._id("approval"),
            capability_id=grant.capability_id,
            tenant=grant.tenant,
            approver=request.approver,
            intent_fingerprint=intent_fingerprint(request.intent),
            issued_at=now,
            expires_at=min(now + request.ttl_seconds, grant.expires_at),
            max_uses=request.max_uses,
        )
        self._state.store_approval(approval)
        self._audit.append(
            actor=request.approver.id,
            action="identity:approve",
            resource=f"capability:{grant.capability_id}",
            decision="approved",
            detail={
                "approval_id": approval.approval_id,
                "expires_at": str(approval.expires_at),
                "intent": approval.intent_fingerprint,
            },
        )
        return approval

    def revoke(self, request: RevokeCapabilityRequest) -> None:
        """Revoke a capability idempotently."""
        self._state.revoke(request.capability_id, request.reason)
        self._audit.append(
            actor=request.revoked_by.id,
            action="identity:revoke",
            resource=f"capability:{request.capability_id}",
            decision="revoked",
            detail={"reason": request.reason},
        )

    def _static_reason(
        self,
        grant: CapabilityGrant,
        intent: AuthorizationIntent,
        now: int,
    ) -> DecisionReason:
        """Evaluate signed scope and time constraints before consuming state."""
        checks = (
            (now < grant.not_before, DecisionReason.NOT_YET_VALID),
            (now >= grant.expires_at, DecisionReason.EXPIRED),
            (
                intent.tenant != grant.tenant or intent.actor.tenant != grant.tenant,
                DecisionReason.TENANT_MISMATCH,
            ),
            (intent.actor != grant.subject, DecisionReason.PRINCIPAL_MISMATCH),
            (intent.audience != grant.audience, DecisionReason.AUDIENCE_MISMATCH),
            (intent.action not in grant.actions, DecisionReason.ACTION_DENIED),
            (
                not request_resource_allowed(grant.resources, intent.resource),
                DecisionReason.RESOURCE_DENIED,
            ),
        )
        for failed, reason in checks:
            if failed:
                return reason
        context_matches = all(
            intent.context.get(key) == expected
            for key, expected in grant.context_constraints.items()
        )
        return DecisionReason.ALLOW if context_matches else DecisionReason.CONTEXT_MISMATCH

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Return an audited, deny-by-default authorization decision."""
        now = self._clock()
        grant: CapabilityGrant | None = None
        try:
            grant = self._codec.decode(request.token)
            reason = self._static_reason(grant, request, now)
        except IntegrityError:
            reason = DecisionReason.INVALID_TOKEN

        remaining: int | None = None
        if grant is not None:
            remaining = self._state.remaining_uses(grant.capability_id, grant.max_uses)
            if reason is DecisionReason.ALLOW:
                consumed = self._state.consume(
                    ConsumeRequest(
                        capability_id=grant.capability_id,
                        max_uses=grant.max_uses,
                        request_id=request.request_id,
                        now=now,
                        approval_required=grant.requires_approval,
                        approval_id=request.approval_id,
                        intent_fingerprint=intent_fingerprint(request),
                    )
                )
                reason = consumed.reason
                remaining = consumed.remaining_uses

        allowed = reason is DecisionReason.ALLOW
        decision = AuthorizationDecision(
            decision_id=self._id("decision"),
            request_id=request.request_id,
            allowed=allowed,
            reason=reason,
            evaluated_at=now,
            capability_id=grant.capability_id if grant else None,
            subject=grant.subject if grant else None,
            remaining_uses=remaining,
        )
        self._audit.append(
            actor=request.actor.id,
            action="authorization:check",
            resource=request.resource,
            decision="allow" if allowed else "deny",
            detail={
                "decision_id": decision.decision_id,
                "request_id": request.request_id,
                "reason": reason.value,
                "capability_id": decision.capability_id or "",
                "action": request.action,
                "tenant": request.tenant,
                "audience": request.audience,
                "context_sha256": content_id(request.context),
            },
        )
        return decision
