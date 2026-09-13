"""Run a complete delegated agent-authorization flow without external services."""

from __future__ import annotations

import json
import secrets
import sys

from aegis.governance.audit import AuditLog
from aegis.identity import (
    ApprovalRequest,
    AuthorizationIntent,
    AuthorizationRequest,
    CapabilityCodec,
    DelegateCapabilityRequest,
    IdentityControlPlane,
    IssueCapabilityRequest,
    Principal,
    PrincipalKind,
)


def main() -> None:
    """Issue, delegate, approve, authorize, and verify one reference workflow."""
    audit = AuditLog()
    plane = IdentityControlPlane(CapabilityCodec(secrets.token_bytes(32)), audit)

    administrator = Principal(
        id="human:platform-admin",
        kind=PrincipalKind.HUMAN,
        tenant="acme",
    )
    planner = Principal(
        id="agent:planner",
        kind=PrincipalKind.AGENT,
        tenant="acme",
    )
    executor = Principal(
        id="agent:invoice-executor",
        kind=PrincipalKind.AGENT,
        tenant="acme",
    )

    root = plane.issue(
        IssueCapabilityRequest(
            issuer=administrator,
            subject=planner,
            audience="service:payments",
            actions=("invoice.read", "invoice.submit"),
            resources=("ledger://acme/invoices/**",),
            ttl_seconds=600,
            max_uses=3,
            requires_approval=True,
            context_constraints={"environment": "demo"},
        )
    )
    child = plane.delegate(
        DelegateCapabilityRequest(
            parent_token=root.token,
            delegated_by=planner,
            subject=executor,
            actions=("invoice.submit",),
            resources=("ledger://acme/invoices/2026/09",),
            ttl_seconds=300,
            max_uses=1,
            requires_approval=True,
            context_constraints={"environment": "demo", "workflow": "month-close"},
        )
    )
    intent = AuthorizationIntent(
        actor=executor,
        tenant="acme",
        audience="service:payments",
        action="invoice.submit",
        resource="ledger://acme/invoices/2026/09",
        context={"environment": "demo", "workflow": "month-close"},
    )
    approval = plane.approve(
        ApprovalRequest(
            capability_token=child.token,
            approver=administrator,
            intent=intent,
            ttl_seconds=120,
        )
    )
    decision = plane.authorize(
        AuthorizationRequest(
            **intent.model_dump(mode="python"),
            token=child.token,
            request_id="demo-request-001",
            approval_id=approval.approval_id,
        )
    )
    audit.verify()

    output = {
        "root_capability_id": root.grant.capability_id,
        "child_capability_id": child.grant.capability_id,
        "delegation_depth": child.grant.delegation_depth,
        "decision": decision.reason,
        "allowed": decision.allowed,
        "remaining_uses": decision.remaining_uses,
        "audit_records": len(audit),
        "audit_verified": True,
    }
    sys.stdout.write(json.dumps(output, indent=2, default=str) + "\n")


if __name__ == "__main__":
    main()
