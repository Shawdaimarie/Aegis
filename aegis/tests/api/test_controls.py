"""Switch access, tenant isolation, durable state and actual authorization enforcement."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from aegis.api.v1.app import create_app
from tests.api.test_identity_v1 import AUTH, authorization_body, issue_body, principal

ADMIN = {"Authorization": "Bearer local-admin-control-secret"}
USER = {"Authorization": "Bearer local-user-control-secret"}
STAFF = {"Authorization": "Bearer local-staff-control-secret"}
OTHER = {"Authorization": "Bearer local-other-control-secret"}
READER = {"Authorization": "Bearer local-reader-control-secret"}


def operator(subject, secret, role="admin", tenant="acme", permissions=()):
    return {
        "subject": subject,
        "tenant": tenant,
        "role": role,
        "token_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "permissions": list(permissions),
    }


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_API_TOKEN", "test-token")
    monkeypatch.setenv("AEGIS_CAPABILITY_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", "separate-human-test-key")
    monkeypatch.setenv("AEGIS_APPROVER_SUBJECT", "human:reviewer")
    monkeypatch.setenv("AEGIS_APPROVER_TENANT", "acme")
    path = tmp_path / "controls.sqlite3"
    monkeypatch.setenv("AEGIS_CONTROL_DB_PATH", str(path))
    operators = [
        operator("human:admin", "local-admin-control-secret"),
        operator(
            "human:user", "local-user-control-secret", "user", permissions=("automation_enabled",)
        ),
        operator(
            "human:staff",
            "local-staff-control-secret",
            "authorized_personnel",
            permissions=("require_human_approval",),
        ),
        operator("human:other", "local-other-control-secret", tenant="other"),
        operator("human:reader", "local-reader-control-secret", "user"),
    ]
    monkeypatch.setenv("AEGIS_CONTROL_OPERATORS", json.dumps(operators))
    return TestClient(create_app()), path, operators


def change(client, setting, enabled, revision, headers=ADMIN, **extra):
    return client.patch(
        "/v1/controls",
        headers=headers,
        json={
            "setting": setting,
            "enabled": enabled,
            "expected_revision": revision,
            "reason": "Operator test decision",
            **extra,
        },
    )


def check(client, token, request_id, approval_id=None):
    return client.post(
        "/v1/authorization/check",
        headers=AUTH,
        json=authorization_body(token, request_id=request_id, approval_id=approval_id),
    )


def test_independent_switches_permissions_and_safe_defaults(setup):
    client, _, _ = setup
    settings = client.get("/v1/controls", headers=ADMIN).json()["settings"]
    assert settings == {
        "tenant": "acme",
        "automation_enabled": False,
        "require_human_approval": True,
        "revision": 0,
    }
    assert change(client, "automation_enabled", True, 0, USER).status_code == 200
    assert change(client, "require_human_approval", False, 1, USER).status_code == 403
    saved = change(client, "require_human_approval", False, 1, STAFF).json()["settings"]
    assert saved["automation_enabled"] is True
    assert saved["require_human_approval"] is False
    assert change(client, "automation_enabled", False, 2, STAFF).status_code == 403
    assert change(client, "automation_enabled", False, 2, ADMIN).status_code == 200
    assert change(client, "automation_enabled", True, 3, READER).status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        {},
        AUTH,
        {"Authorization": "Bearer wrong"},
        {"Authorization": "Bearer separate-human-test-key"},
    ],
)
def test_only_separately_registered_operators_can_access_controls(setup, headers):
    client, _, _ = setup
    assert client.get("/v1/controls", headers=headers).status_code == 401
    assert change(client, "automation_enabled", True, 0, headers).status_code == 401
    assert client.get("/v1/controls/history", headers=headers).status_code == 401


def test_tenant_is_server_owned_and_audit_survives_restart(setup):
    client, _, _ = setup
    assert change(client, "automation_enabled", True, 0, tenant="other").status_code == 422
    assert change(client, "automation_enabled", True, 0, actor="fake").status_code == 422
    assert change(client, "automation_enabled", True, 0).status_code == 200
    restarted = TestClient(create_app())
    assert restarted.get("/v1/controls", headers=ADMIN).json()["settings"]["automation_enabled"]
    assert not restarted.get("/v1/controls", headers=OTHER).json()["settings"]["automation_enabled"]
    events = restarted.get("/v1/controls/history", headers=ADMIN).json()
    assert len(events) == 1
    assert events[0]["actor"] == "human:admin"
    assert events[0]["before"]["revision"] == 0
    assert events[0]["after"]["revision"] == 1
    assert restarted.get("/v1/controls/history", headers=OTHER).json() == []


def test_parallel_stale_changes_cannot_overwrite(setup):
    client, _, _ = setup
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: change(client, "automation_enabled", True, 0).status_code, range(2))
        )
    assert sorted(results) == [200, 409]
    assert len(client.get("/v1/controls/history", headers=ADMIN).json()) == 1


@pytest.mark.parametrize(
    "extra",
    [
        {"enabled": "false"},
        {"enabled": 0},
        {"expected_revision": True},
        {"reason": "  "},
        {"setting": "authentication_enabled"},
    ],
)
def test_strict_change_contract(setup, extra):
    client, _, _ = setup
    body = {
        "setting": "automation_enabled",
        "enabled": True,
        "expected_revision": 0,
        "reason": "test decision",
    }
    body.update(extra)
    assert client.patch("/v1/controls", json=body, headers=ADMIN).status_code == 422


@pytest.mark.parametrize("bad", ["missing", "invalid", "duplicate", "service", "reviewer"])
def test_invalid_operator_configuration_fails_closed(setup, monkeypatch, bad):
    client, _, operators = setup
    if bad == "missing":
        monkeypatch.delenv("AEGIS_CONTROL_OPERATORS")
    elif bad == "invalid":
        monkeypatch.setenv("AEGIS_CONTROL_OPERATORS", "not-json")
    else:
        if bad == "duplicate":
            operators.append(operators[0])
        else:
            secret = "test-token" if bad == "service" else "separate-human-test-key"
            operators[0]["token_sha256"] = hashlib.sha256(secret.encode()).hexdigest()
        monkeypatch.setenv("AEGIS_CONTROL_OPERATORS", json.dumps(operators))
    assert client.get("/v1/controls", headers=ADMIN).status_code == 503


def test_enforcement_pause_global_approval_and_capability_floor(setup):
    client, _, _ = setup
    issued = client.post(
        "/v1/identity/capabilities", json=issue_body(max_uses=5), headers=AUTH
    ).json()
    token = issued["token"]
    paused = check(client, token, "paused").json()
    assert paused["reason"] == "automation_paused"
    assert paused["remaining_uses"] == 5
    change(client, "automation_enabled", True, 0)
    assert check(client, token, "needs-approval").json()["reason"] == "approval_required"
    intent = authorization_body(token, request_id="intent-only")
    for key in ("token", "request_id", "approval_id"):
        intent.pop(key)
    approval = client.post(
        "/v1/identity/approvals",
        headers={"Authorization": "Bearer separate-human-test-key"},
        json={
            "capability_token": token,
            "intent": intent,
            "approver": principal("human:reviewer", "human"),
        },
    ).json()
    assert check(client, token, "approved", approval["approval_id"]).json()["allowed"] is True
    change(client, "require_human_approval", False, 1)
    assert check(client, token, "policy-only").json()["allowed"] is True
    strict = client.post(
        "/v1/identity/capabilities", json=issue_body(approval=True), headers=AUTH
    ).json()
    assert check(client, strict["token"], "still-required").json()["reason"] == "approval_required"
    change(client, "automation_enabled", False, 2)
    assert (
        check(TestClient(create_app()), token, "paused-after-restart").json()["reason"]
        == "automation_paused"
    )


def test_unavailable_storage_and_failed_audit_block_changes(setup, monkeypatch):
    client, path, _ = setup
    client.get("/v1/controls", headers=ADMIN)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER reject_event BEFORE INSERT ON control_events "
            "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
        )
    assert change(client, "automation_enabled", True, 0).status_code == 503
    assert client.get("/v1/controls", headers=ADMIN).json()["settings"]["revision"] == 0
    monkeypatch.delenv("AEGIS_CONTROL_DB_PATH")
    issued = client.post("/v1/identity/capabilities", json=issue_body(), headers=AUTH).json()
    assert check(client, issued["token"], "unavailable").status_code == 503
    assert client.get("/v1/controls", headers=ADMIN).status_code == 503


def test_corrupt_or_relative_storage_fails_closed(setup, monkeypatch):
    client, path, _ = setup
    change(client, "automation_enabled", True, 0)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE control_settings SET settings = 'broken'")
    assert client.get("/v1/controls", headers=ADMIN).status_code == 503
    monkeypatch.setenv("AEGIS_CONTROL_DB_PATH", "relative.sqlite3")
    assert client.get("/v1/controls", headers=ADMIN).status_code == 503


def test_control_pages_cannot_be_framed_or_cached(setup):
    client, _, _ = setup
    for path in ("/console/", "/v1/controls", "/v1/controls/history"):
        response = client.get(path, headers=ADMIN)
        assert response.status_code == 200
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "base-uri 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"
