from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.adapters.control_settings import ControlChange, ControlSettingsStore
from aegis.api.v1.app import create_app

AUTH = {"Authorization": "Bearer test-token", "X-Aegis-Subject": "control-plane-admin"}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path) -> TestClient:
    monkeypatch.setenv("AEGIS_API_TOKEN", "test-token")
    monkeypatch.setenv("AEGIS_CAPABILITY_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", "separate-human-test-key")
    monkeypatch.setenv("AEGIS_APPROVER_SUBJECT", "human:reviewer")
    monkeypatch.setenv("AEGIS_APPROVER_TENANT", "acme")
    path = tmp_path / "controls.sqlite3"
    monkeypatch.setenv("AEGIS_CONTROL_DB_PATH", str(path))
    store = ControlSettingsStore(path)
    for revision, (setting, enabled) in enumerate(
        [("automation_enabled", True), ("require_human_approval", False)]
    ):
        store.change(
            "acme",
            ControlChange(
                setting=setting,
                enabled=enabled,
                expected_revision=revision,
                reason="Legacy test policy",
            ),
            actor="human:test-admin",
            role="admin",
        )
    return TestClient(create_app())


def principal(identifier: str, kind: str = "agent", tenant: str = "acme") -> dict[str, str]:
    return {"id": identifier, "kind": kind, "tenant": tenant}


def issue_body(*, approval: bool = False, max_uses: int = 2) -> dict[str, object]:
    return {
        "issuer": principal("api-client", "service"),
        "subject": principal("agent:planner"),
        "audience": "service:payments",
        "actions": ["payment.read", "payment.submit"],
        "resources": ["ledger://acme/invoices/**"],
        "ttl_seconds": 600,
        "max_uses": max_uses,
        "requires_approval": approval,
        "context_constraints": {"environment": "production"},
    }


def authorization_body(
    token: str, *, request_id: str, approval_id: str | None = None
) -> dict[str, object]:
    return {
        "token": token,
        "request_id": request_id,
        "approval_id": approval_id,
        "actor": principal("agent:planner"),
        "tenant": "acme",
        "audience": "service:payments",
        "action": "payment.read",
        "resource": "ledger://acme/invoices/2026-09",
        "context": {"environment": "production"},
    }


def test_identity_endpoints_require_admin_auth(client: TestClient) -> None:
    assert client.post("/v1/identity/capabilities", json=issue_body()).status_code == 401
    assert client.post("/v1/authorization/check", json={}).status_code == 401


def test_issue_inspect_authorize_and_replay(client: TestClient) -> None:
    issued_response = client.post("/v1/identity/capabilities", json=issue_body(), headers=AUTH)
    assert issued_response.status_code == 201
    issued = issued_response.json()
    token = issued["token"]

    inspected = client.post(
        "/v1/identity/capabilities/inspect", json={"token": token}, headers=AUTH
    )
    assert inspected.status_code == 200
    assert inspected.json()["subject"]["id"] == "agent:planner"

    allowed = client.post(
        "/v1/authorization/check",
        json=authorization_body(token, request_id="request-api-001"),
        headers=AUTH,
    )
    assert allowed.status_code == 200
    assert allowed.json()["allowed"] is True
    assert allowed.json()["reason"] == "allow"

    replay = client.post(
        "/v1/authorization/check",
        json=authorization_body(token, request_id="request-api-001"),
        headers=AUTH,
    )
    assert replay.json()["allowed"] is False
    assert replay.json()["reason"] == "replay_detected"


def test_approval_and_revocation_paths(client: TestClient) -> None:
    issued = client.post(
        "/v1/identity/capabilities", json=issue_body(approval=True), headers=AUTH
    ).json()
    token = issued["token"]
    intent = authorization_body(token, request_id="placeholder")
    intent.pop("token")
    intent.pop("request_id")
    intent.pop("approval_id")

    missing = client.post(
        "/v1/authorization/check",
        json=authorization_body(token, request_id="request-api-missing-approval"),
        headers=AUTH,
    ).json()
    assert missing["reason"] == "approval_required"

    approval_response = client.post(
        "/v1/identity/approvals",
        json={
            "capability_token": token,
            "approver": principal("human:reviewer", "human"),
            "intent": intent,
            "ttl_seconds": 300,
            "max_uses": 1,
        },
        headers={"Authorization": "Bearer separate-human-test-key"},
    )
    assert approval_response.status_code == 201
    approval_id = approval_response.json()["approval_id"]

    allowed = client.post(
        "/v1/authorization/check",
        json=authorization_body(
            token,
            request_id="request-api-approved",
            approval_id=approval_id,
        ),
        headers=AUTH,
    ).json()
    assert allowed["allowed"] is True

    revoked = client.post(
        "/v1/identity/revocations",
        json={
            "capability_id": issued["grant"]["capability_id"],
            "revoked_by": principal("api-client", "service"),
            "reason": "incident response containment",
        },
        headers=AUTH,
    )
    assert revoked.status_code == 204

    denied = client.post(
        "/v1/authorization/check",
        json=authorization_body(token, request_id="request-api-revoked"),
        headers=AUTH,
    ).json()
    assert denied["reason"] == "revoked"


def test_delegation_endpoint_prevents_scope_broadening(client: TestClient) -> None:
    parent = client.post(
        "/v1/identity/capabilities", json=issue_body(max_uses=3), headers=AUTH
    ).json()
    child_body = {
        "parent_token": parent["token"],
        "delegated_by": principal("agent:planner"),
        "subject": principal("agent:executor"),
        "actions": ["payment.read"],
        "resources": ["ledger://acme/invoices/2026/**"],
        "ttl_seconds": 300,
        "max_uses": 1,
        "context_constraints": {"environment": "production", "region": "us"},
    }
    child = client.post("/v1/identity/capabilities/delegate", json=child_body, headers=AUTH)
    assert child.status_code == 201
    assert child.json()["grant"]["delegation_depth"] == 1

    broadened = dict(child_body)
    broadened["resources"] = ["ledger://acme/**"]
    rejected = client.post("/v1/identity/capabilities/delegate", json=broadened, headers=AUTH)
    assert rejected.status_code == 422


def test_invalid_capability_fails_closed_with_reason_code(client: TestClient) -> None:
    issued = client.post("/v1/identity/capabilities", json=issue_body(), headers=AUTH).json()
    token = issued["token"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    body = authorization_body(tampered, request_id="request-api-invalid")
    decision = client.post("/v1/authorization/check", json=body, headers=AUTH)
    assert decision.status_code == 200
    assert decision.json()["allowed"] is False
    assert decision.json()["reason"] == "invalid_token"


REVIEWER = {"Authorization": "Bearer separate-human-test-key"}


def review_proposal(client: TestClient) -> dict[str, object]:
    issued = client.post(
        "/v1/identity/capabilities", json=issue_body(approval=True), headers=AUTH
    ).json()
    intent = authorization_body(issued["token"], request_id="review")
    for key in ("token", "request_id", "approval_id"):
        intent.pop(key)
    return {"capability_token": issued["token"], "intent": intent}


def test_review_profile_rejects_service_and_preserves_named_identity(client: TestClient) -> None:
    assert client.get("/v1/reviews/me", headers=AUTH).status_code == 401
    profile = client.get("/v1/reviews/me", headers=REVIEWER)
    assert profile.json()["subject"] == "human:reviewer"
    assert profile.json()["tenant"] == "acme"
    assert profile.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in profile.headers["content-security-policy"]


def test_review_preview_does_not_grant_authority_and_approval_is_single_use(
    client: TestClient,
) -> None:
    proposal = review_proposal(client)
    preview = client.post("/v1/reviews/preview", json=proposal, headers=REVIEWER)
    assert preview.status_code == 200
    assert "capability_token" not in preview.json()
    assert "approval_id" not in preview.json()
    request = authorization_body(str(proposal["capability_token"]), request_id="review-before")
    assert (
        client.post("/v1/authorization/check", json=request, headers=AUTH).json()["reason"]
        == "approval_required"
    )
    approved = client.post("/v1/reviews/approve", json=proposal, headers=REVIEWER)
    assert approved.status_code == 201
    assert approved.json()["approver"]["id"] == "human:reviewer"
    request.update(approval_id=approved.json()["approval_id"], request_id="review-after")
    assert client.post("/v1/authorization/check", json=request, headers=AUTH).json()["allowed"]
    request["request_id"] = "review-again"
    assert not client.post("/v1/authorization/check", json=request, headers=AUTH).json()["allowed"]


@pytest.mark.parametrize(
    ("field", "value"),
    [("approver", {"id": "human:forged"}), ("max_uses", 2), ("ttl_seconds", 301)],
)
def test_review_rejects_identity_injection_and_expanded_limits(
    client: TestClient, field, value
) -> None:
    proposal = review_proposal(client)
    proposal[field] = value
    assert client.post("/v1/reviews/approve", json=proposal, headers=REVIEWER).status_code == 422


def test_review_revalidates_revocation_after_preview(client: TestClient) -> None:
    proposal = review_proposal(client)
    preview = client.post("/v1/reviews/preview", json=proposal, headers=REVIEWER).json()
    client.post(
        "/v1/identity/revocations",
        json={
            "capability_id": preview["capability_id"],
            "revoked_by": principal("api-client", "service"),
            "reason": "Withdraw before approval",
        },
        headers=AUTH,
    )
    assert client.post("/v1/reviews/approve", json=proposal, headers=REVIEWER).status_code == 422


def test_review_tenant_and_scope_boundaries(client: TestClient) -> None:
    proposal = review_proposal(client)
    proposal["intent"]["tenant"] = "another"
    assert client.post("/v1/reviews/preview", json=proposal, headers=REVIEWER).status_code == 403
    proposal["intent"]["tenant"] = "acme"
    proposal["intent"]["action"] = "payment.delete"
    assert client.post("/v1/reviews/preview", json=proposal, headers=REVIEWER).status_code == 422
    assert client.post("/v1/reviews/approve", json=proposal, headers=REVIEWER).status_code == 422
