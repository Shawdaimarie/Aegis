import pytest
from fastapi.testclient import TestClient

from aegis.api.v1.app import create_app

AUTH = {"Authorization": "Bearer test-token"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AEGIS_API_TOKEN", "test-token")
    return TestClient(create_app())


def test_caller_cannot_impersonate_human_in_audit(client):
    response = client.post(
        "/v1/governance/evaluate",
        json={"checkpoint": "pre_run", "context": {"run_id": "r", "scenario": "independent"}},
        headers={**AUTH, "X-Aegis-Subject": "human-owner-approved"},
    )
    assert response.status_code == 200
    records = client.get("/v1/audit", headers=AUTH).json()["records"]
    assert records[-1]["actor"] == "api-client"
    assert "human-owner-approved" not in str(records)


@pytest.mark.parametrize("length", [None, "1"])
def test_actual_body_limit_applies_without_truthful_content_length(client, length):
    headers = dict(AUTH)
    if length is not None:
        headers["Content-Length"] = length
    response = client.post(
        "/v1/governance/evaluate",
        content=iter([b"x" * 131072, b"x" * 131073]),
        headers=headers,
    )
    assert response.status_code == 413


@pytest.mark.parametrize("length", ["-1", "not-an-integer"])
def test_malformed_content_length_is_not_a_server_error(client, length):
    response = client.post(
        "/v1/governance/evaluate", content=b"{}", headers={**AUTH, "Content-Length": length}
    )
    assert response.status_code == 400


@pytest.mark.parametrize("value", ['"NaN"', "NaN", '"Infinity"', "1e999"])
def test_nonfinite_telemetry_cannot_bypass_threshold(client, value):
    body = (
        '{"checkpoint":"step","context":{"run_id":"r","scenario":"independent","metrics":{"loss":'
        + value
        + "}}}"
    )
    response = client.post(
        "/v1/governance/evaluate",
        content=body,
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_missing_safety_measurement_is_denied(client):
    response = client.post(
        "/v1/governance/evaluate",
        headers=AUTH,
        json={"checkpoint": "step", "context": {"run_id": "r", "scenario": "independent"}},
    )
    assert response.status_code == 200
    assert response.json()["allowed"] is False


@pytest.mark.parametrize("override", [{"steps": 1001}, {"governance_cadence": 1000}])
def test_simulation_cannot_expand_server_budget_or_skip_checks(client, override):
    spec = {
        "run_id": "sim-safe",
        "scenario": "independent",
        "root_seed": 1,
        "steps": 5,
        "dataset_hash": "sha256:" + "b" * 64,
        "git_commit": "abcdef1",
        "config_hash": "c",
        "env_lock_hash": "e",
        **override,
    }
    assert client.post("/v1/runs/simulate", json={"spec": spec}, headers=AUTH).status_code == 422
