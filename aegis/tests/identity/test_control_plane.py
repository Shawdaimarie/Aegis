from __future__ import annotations

from collections.abc import Callable

import pytest

from aegis.core.errors import IntegrityError
from aegis.governance.audit import AuditLog
from aegis.identity import (
    ApprovalRequest,
    AuthorizationIntent,
    AuthorizationRequest,
    CapabilityCodec,
    DecisionReason,
    DelegateCapabilityRequest,
    IdentityControlPlane,
    IssueCapabilityRequest,
    Principal,
    PrincipalKind,
    RevokeCapabilityRequest,
)


class MutableClock:
    def __init__(self, value: int = 1_800_000_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def plane(clock: MutableClock, audit: AuditLog) -> IdentityControlPlane:
    return IdentityControlPlane(CapabilityCodec("k" * 32), audit, clock=clock)


@pytest.fixture
def principals() -> dict[str, Principal]:
    return {
        "admin": Principal(id="human:admin", kind=PrincipalKind.HUMAN, tenant="acme"),
        "agent": Principal(id="agent:planner", kind=PrincipalKind.AGENT, tenant="acme"),
        "child": Principal(id="agent:executor", kind=PrincipalKind.AGENT, tenant="acme"),
        "other": Principal(id="agent:other", kind=PrincipalKind.AGENT, tenant="other"),
    }


def issue_default(
    plane: IdentityControlPlane,
    principals: dict[str, Principal],
    **overrides: object,
):
    values: dict[str, object] = {
        "issuer": principals["admin"],
        "subject": principals["agent"],
        "audience": "service:payments",
        "actions": ("payment.read", "payment.submit"),
        "resources": ("ledger://acme/invoices/**",),
        "ttl_seconds": 600,
        "max_uses": 2,
        "requires_approval": False,
        "context_constraints": {"environment": "production"},
    }
    values.update(overrides)
    return plane.issue(IssueCapabilityRequest.model_validate(values))


def intent(principals: dict[str, Principal], **overrides: object) -> AuthorizationIntent:
    values: dict[str, object] = {
        "actor": principals["agent"],
        "tenant": "acme",
        "audience": "service:payments",
        "action": "payment.read",
        "resource": "ledger://acme/invoices/2026-09",
        "context": {"environment": "production"},
    }
    values.update(overrides)
    return AuthorizationIntent.model_validate(values)


def auth_request(
    token: str,
    principals: dict[str, Principal],
    *,
    request_id: str = "request-001",
    approval_id: str | None = None,
    **overrides: object,
) -> AuthorizationRequest:
    payload = intent(principals, **overrides).model_dump(mode="python")
    payload.update({"token": token, "request_id": request_id, "approval_id": approval_id})
    return AuthorizationRequest.model_validate(payload)


def test_codec_round_trip_and_tamper_detection(principals, plane):
    issued = issue_default(plane, principals)
    assert plane.inspect(issued.token) == issued.grant

    prefix, key_id, payload, signature = issued.token.split(".")
    replacement = "A" if payload[-1] != "A" else "B"
    tampered = ".".join((prefix, key_id, payload[:-1] + replacement, signature))
    with pytest.raises(IntegrityError, match="signature"):
        plane.inspect(tampered)


def test_codec_rejects_weak_or_wrong_key(principals):
    with pytest.raises(ValueError, match="at least 32 bytes"):
        CapabilityCodec("weak")

    issuer = IdentityControlPlane(
        CapabilityCodec("a" * 32), AuditLog(), clock=lambda: 1_800_000_000
    )
    issued = issuer.issue(
        IssueCapabilityRequest(
            issuer=principals["admin"],
            subject=principals["agent"],
            audience="service:payments",
            actions=("payment.read",),
            resources=("ledger://acme/invoices/**",),
            ttl_seconds=60,
        )
    )
    verifier = IdentityControlPlane(
        CapabilityCodec("b" * 32), AuditLog(), clock=lambda: 1_800_000_000
    )
    with pytest.raises(IntegrityError, match="signature"):
        verifier.inspect(issued.token)


def test_authorizes_in_scope_then_enforces_replay_and_use_budget(plane, principals, audit):
    issued = issue_default(plane, principals)
    first = plane.authorize(auth_request(issued.token, principals, request_id="request-001"))
    assert first.allowed is True
    assert first.reason is DecisionReason.ALLOW
    assert first.remaining_uses == 1

    replay = plane.authorize(auth_request(issued.token, principals, request_id="request-001"))
    assert replay.allowed is False
    assert replay.reason is DecisionReason.REPLAY_DETECTED
    assert replay.remaining_uses == 1

    second = plane.authorize(auth_request(issued.token, principals, request_id="request-002"))
    exhausted = plane.authorize(auth_request(issued.token, principals, request_id="request-003"))
    assert second.allowed is True
    assert second.remaining_uses == 0
    assert exhausted.reason is DecisionReason.USE_BUDGET_EXHAUSTED
    audit.verify()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        (
            {"actor": Principal(id="agent:intruder", kind="agent", tenant="acme")},
            DecisionReason.PRINCIPAL_MISMATCH,
        ),
        (
            {
                "tenant": "other",
                "actor": Principal(id="agent:intruder", kind="agent", tenant="other"),
            },
            DecisionReason.TENANT_MISMATCH,
        ),
        ({"audience": "service:storage"}, DecisionReason.AUDIENCE_MISMATCH),
        ({"action": "payment.delete"}, DecisionReason.ACTION_DENIED),
        ({"resource": "ledger://other/invoices/1"}, DecisionReason.RESOURCE_DENIED),
        ({"context": {"environment": "staging"}}, DecisionReason.CONTEXT_MISMATCH),
    ],
)
def test_static_scope_failures_are_stable_reason_codes(plane, principals, overrides, reason):
    issued = issue_default(plane, principals)
    decision = plane.authorize(
        auth_request(issued.token, principals, request_id=f"request-{reason.value}", **overrides)
    )
    assert decision.allowed is False
    assert decision.reason is reason


def test_not_before_expiration_and_revocation(plane, principals, clock):
    future = issue_default(plane, principals, not_before_seconds=30)
    early = plane.authorize(auth_request(future.token, principals, request_id="request-early"))
    assert early.reason is DecisionReason.NOT_YET_VALID

    clock.value += 31
    active = plane.authorize(auth_request(future.token, principals, request_id="request-active"))
    assert active.allowed

    clock.value += 600
    expired = plane.authorize(auth_request(future.token, principals, request_id="request-expired"))
    assert expired.reason is DecisionReason.EXPIRED

    clock.value = 1_800_000_000
    issued = issue_default(plane, principals)
    plane.revoke(
        RevokeCapabilityRequest(
            capability_id=issued.grant.capability_id,
            revoked_by=principals["admin"],
            reason="incident containment",
        )
    )
    revoked = plane.authorize(auth_request(issued.token, principals, request_id="request-revoked"))
    assert revoked.reason is DecisionReason.REVOKED


def test_human_approval_is_bound_to_exact_intent(plane, principals):
    issued = issue_default(plane, principals, requires_approval=True, max_uses=3)
    intended = intent(principals, action="payment.submit")

    missing = plane.authorize(
        auth_request(
            issued.token,
            principals,
            action="payment.submit",
            request_id="request-no-approval",
        )
    )
    assert missing.reason is DecisionReason.APPROVAL_REQUIRED

    approval = plane.approve(
        ApprovalRequest(
            capability_token=issued.token,
            approver=principals["admin"],
            intent=intended,
            max_uses=1,
        )
    )
    allowed = plane.authorize(
        auth_request(
            issued.token,
            principals,
            action="payment.submit",
            request_id="request-approved",
            approval_id=approval.approval_id,
        )
    )
    assert allowed.allowed is True

    reuse = plane.authorize(
        auth_request(
            issued.token,
            principals,
            action="payment.submit",
            request_id="request-reuse-approval",
            approval_id=approval.approval_id,
        )
    )
    assert reuse.reason is DecisionReason.APPROVAL_INVALID

    wrong_resource_approval = plane.approve(
        ApprovalRequest(
            capability_token=issued.token,
            approver=principals["admin"],
            intent=intended,
        )
    )
    wrong_resource = plane.authorize(
        auth_request(
            issued.token,
            principals,
            action="payment.submit",
            resource="ledger://acme/invoices/different",
            request_id="request-wrong-approval-intent",
            approval_id=wrong_resource_approval.approval_id,
        )
    )
    assert wrong_resource.reason is DecisionReason.APPROVAL_INVALID


def delegate_default(plane, principals, token, **overrides):
    values = {
        "parent_token": token,
        "delegated_by": principals["agent"],
        "subject": principals["child"],
        "actions": ("payment.read",),
        "resources": ("ledger://acme/invoices/2026/**",),
        "ttl_seconds": 300,
        "max_uses": 1,
        "requires_approval": False,
        "context_constraints": {"environment": "production", "region": "us"},
    }
    values.update(overrides)
    return plane.delegate(DelegateCapabilityRequest.model_validate(values))


def test_delegation_is_narrower_and_reserves_parent_budget(plane, principals):
    parent = issue_default(plane, principals, max_uses=2)
    child = delegate_default(plane, principals, parent.token)
    assert child.grant.parent_capability_id == parent.grant.capability_id
    assert child.grant.delegation_depth == 1

    child_request = AuthorizationRequest(
        token=child.token,
        request_id="request-child",
        actor=principals["child"],
        tenant="acme",
        audience="service:payments",
        action="payment.read",
        resource="ledger://acme/invoices/2026/09",
        context={"environment": "production", "region": "us"},
    )
    assert plane.authorize(child_request).allowed is True

    parent_first = plane.authorize(
        auth_request(parent.token, principals, request_id="request-parent-after-delegation")
    )
    parent_second = plane.authorize(
        auth_request(parent.token, principals, request_id="request-parent-exhausted")
    )
    assert parent_first.allowed is True
    assert parent_first.remaining_uses == 0
    assert parent_second.reason is DecisionReason.USE_BUDGET_EXHAUSTED


def test_parent_revocation_cascades_to_delegated_child(plane, principals):
    parent = issue_default(plane, principals, max_uses=2)
    child = delegate_default(plane, principals, parent.token)
    plane.revoke(
        RevokeCapabilityRequest(
            capability_id=parent.grant.capability_id,
            revoked_by=principals["admin"],
            reason="delegation chain compromised",
        )
    )
    decision = plane.authorize(
        AuthorizationRequest(
            token=child.token,
            request_id="request-revoked-child",
            actor=principals["child"],
            tenant="acme",
            audience="service:payments",
            action="payment.read",
            resource="ledger://acme/invoices/2026/09",
            context={"environment": "production", "region": "us"},
        )
    )
    assert decision.reason is DecisionReason.REVOKED


@pytest.mark.parametrize(
    "factory",
    [
        lambda p: {"actions": ("payment.delete",)},
        lambda p: {"resources": ("ledger://acme/**",)},
        lambda p: {"max_uses": 3},
        lambda p: {"requires_approval": False, "context_constraints": {"region": "us"}},
        lambda p: {"subject": p["other"]},
    ],
)
def test_delegation_rejects_privilege_escalation(plane, principals, factory: Callable):
    parent = issue_default(plane, principals, max_uses=2, requires_approval=True)
    with pytest.raises(ValueError, match=r"delegat|approval|tenant|subject|authority"):
        delegate_default(plane, principals, parent.token, **factory(principals))


def test_every_modified_signature_suffix_is_rejected(plane, principals):
    issued = issue_default(plane, principals)
    codec = CapabilityCodec("k" * 32)
    for suffix in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
        if suffix == issued.token[-1]:
            continue
        with pytest.raises(IntegrityError):
            codec.decode(issued.token[:-1] + suffix)
    assert codec.decode(issued.token) == issued.grant


def test_noncanonical_or_nonascii_token_is_an_integrity_error(plane, principals):
    issued = issue_default(plane, principals)
    prefix, key, payload, signature = issued.token.split(".")
    for token in (issued.token + "=", f"{prefix}.{key}.é{payload}.{signature}"):
        with pytest.raises(IntegrityError):
            CapabilityCodec("k" * 32).decode(token)
