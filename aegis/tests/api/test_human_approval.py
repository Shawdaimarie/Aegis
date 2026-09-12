"""Approval identity comes from authenticated operator configuration, not input."""

import pytest

from tests.api.test_identity_v1 import AUTH, authorization_body, client, issue_body, principal

__all__ = ["client"]


def test_admin_request_cannot_claim_human_issuer(client):
    body = issue_body()
    body["issuer"] = principal("human:owner", "human")
    assert client.post("/v1/identity/capabilities", json=body, headers=AUTH).status_code == 403


def approval_body(client):
    issued = client.post(
        "/v1/identity/capabilities", json=issue_body(approval=True), headers=AUTH
    ).json()
    intent = authorization_body(issued["token"], request_id="approval-test")
    for key in ("token", "request_id", "approval_id"):
        intent.pop(key)
    return {
        "capability_token": issued["token"],
        "approver": principal("human:reviewer", "human"),
        "intent": intent,
    }


def test_service_token_cannot_self_approve(client):
    body = approval_body(client)
    assert client.post("/v1/identity/approvals", json=body, headers=AUTH).status_code == 401
    audit = client.get("/v1/audit", headers=AUTH).json()
    assert all(record["action"] != "identity:approve" for record in audit["records"])


def test_approved_credential_cannot_claim_a_different_human(client):
    body = approval_body(client)
    body["approver"] = principal("human:someone-else", "human")
    response = client.post(
        "/v1/identity/approvals",
        json=body,
        headers={"Authorization": "Bearer separate-human-test-key"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("misconfiguration", ["missing", "same-as-service"])
def test_approval_fails_closed_without_separate_identity(client, monkeypatch, misconfiguration):
    body = approval_body(client)
    if misconfiguration == "missing":
        monkeypatch.delenv("AEGIS_APPROVER_TOKEN")
    else:
        monkeypatch.setenv("AEGIS_APPROVER_TOKEN", "test-token")
    assert client.post("/v1/identity/approvals", json=body, headers=AUTH).status_code == 503
