"""The API must not forget authority decisions when a worker restarts."""

import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.adapters.authorization_store import initialize_database
from aegis.api.v1.app import create_app
from aegis.core.errors import ConfigurationError, StateUnavailableError
from tests.api.test_identity_v1 import AUTH, authorization_body, client, issue_body, principal

__all__ = ["client"]


def issued(client, *, approval=False, uses=2):
    response = client.post(
        "/v1/identity/capabilities", headers=AUTH, json=issue_body(approval=approval, max_uses=uses)
    )
    assert response.status_code == 201
    return response.json()


def check(client, token, request_id, approval_id=None):
    return client.post(
        "/v1/authorization/check",
        headers=AUTH,
        json=authorization_body(token, request_id=request_id, approval_id=approval_id),
    )


def test_revocation_remains_denied_after_restart(client):
    grant = issued(client)
    response = client.post(
        "/v1/identity/revocations",
        headers=AUTH,
        json={
            "capability_id": grant["grant"]["capability_id"],
            "revoked_by": principal("api-client", "service"),
            "reason": "Human revocation",
        },
    )
    assert response.status_code == 204
    assert (
        check(TestClient(create_app()), grant["token"], "after-restart").json()["reason"]
        == "revoked"
    )


def test_replay_and_budget_survive_restart(client):
    grant = issued(client)
    assert check(client, grant["token"], "request-first").json()["allowed"]
    restarted = TestClient(create_app())
    assert check(restarted, grant["token"], "request-first").json()["reason"] == "replay_detected"
    assert check(restarted, grant["token"], "request-second").json()["allowed"]
    assert (
        check(TestClient(create_app()), grant["token"], "request-third").json()["reason"]
        == "use_budget_exhausted"
    )


def test_approval_and_its_consumption_survive_restart(client):
    grant = issued(client, approval=True)
    intent = authorization_body(grant["token"], request_id="intent")
    for key in ("token", "request_id", "approval_id"):
        intent.pop(key)
    approval = client.post(
        "/v1/identity/approvals",
        headers={"Authorization": "Bearer separate-human-test-key"},
        json={
            "capability_token": grant["token"],
            "approver": principal("human:reviewer", "human"),
            "intent": intent,
            "max_uses": 1,
        },
    ).json()
    assert check(
        TestClient(create_app()), grant["token"], "approved-first", approval["approval_id"]
    ).json()["allowed"]
    assert (
        check(
            TestClient(create_app()), grant["token"], "approved-twice", approval["approval_id"]
        ).json()["reason"]
        == "approval_invalid"
    )


def test_missing_ledger_is_not_recreated_and_returns_safe_error(client):
    grant = issued(client)
    path = Path(os.environ["AEGIS_AUTHORIZATION_DB_PATH"])
    path.unlink()
    response = check(client, grant["token"], "lost-ledger")
    assert response.status_code == 503
    assert response.json() == {"detail": "authorization state unavailable"}
    assert not path.exists()
    with pytest.raises(StateUnavailableError):
        create_app()


def test_reinitialized_ledger_does_not_accept_old_tokens(client):
    grant = issued(client)
    path = Path(os.environ["AEGIS_AUTHORIZATION_DB_PATH"])
    path.unlink()
    initialize_database(path)
    assert check(client, grant["token"], "replaced-running").status_code == 503
    assert check(TestClient(create_app()), grant["token"], "empty-new-ledger").status_code == 503


def test_startup_requires_configuration_and_separate_ledgers(client, monkeypatch):
    path = os.environ["AEGIS_AUTHORIZATION_DB_PATH"]
    monkeypatch.delenv("AEGIS_AUTHORIZATION_DB_PATH")
    with pytest.raises(ConfigurationError):
        create_app()
    monkeypatch.setenv("AEGIS_AUTHORIZATION_DB_PATH", path)
    monkeypatch.setenv("AEGIS_CONTROL_DB_PATH", path)
    with pytest.raises(ConfigurationError, match="separate"):
        create_app()


def test_schema_damage_denies_requests(client):
    grant = issued(client)
    with sqlite3.connect(os.environ["AEGIS_AUTHORIZATION_DB_PATH"]) as db:
        db.execute("UPDATE metadata SET version=999")
    assert check(client, grant["token"], "wrong-schema").status_code == 503
    with pytest.raises(StateUnavailableError):
        create_app()
