import pytest
from fastapi.testclient import TestClient

from aegis.api.v1.app import create_app

H = "sha256:" + "b" * 64


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AEGIS_API_TOKEN", "test-token")
    monkeypatch.setenv("AEGIS_CAPABILITY_SIGNING_KEY", "k" * 32)
    return TestClient(create_app())


AUTH = {"Authorization": "Bearer test-token"}


def test_health_and_version_are_public(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    r = client.get("/version")
    assert r.json()["api"] == "v1"
    assert r.headers["Content-Security-Policy"] == "default-src 'self'"
    assert "X-Request-ID" in r.headers


def test_boundaries_require_auth(client):
    assert client.get("/v1/governance/boundaries").status_code == 401
    assert (
        client.get(
            "/v1/governance/boundaries", headers={"Authorization": "Bearer nope"}
        ).status_code
        == 401
    )
    assert client.get("/v1/governance/boundaries", headers=AUTH).status_code == 200


def test_evaluate_reports_block(client):
    body = {"checkpoint": "pre_run", "context": {"run_id": "r", "scenario": "independent"}}
    r = client.post("/v1/governance/evaluate", json=body, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["blocked_by"] == "dataset-hash-required"


def test_simulate_completes_and_audit_verifies(client):
    spec = {
        "run_id": "sim-1",
        "scenario": "independent",
        "root_seed": 3,
        "steps": 5,
        "dataset_hash": H,
        "git_commit": "abcdef1",
        "config_hash": "c",
        "env_lock_hash": "e",
    }
    r = client.post("/v1/runs/simulate", json={"spec": spec}, headers=AUTH)
    assert r.status_code == 201
    assert r.json()["outcome"] == "completed"
    a = client.get("/v1/audit?limit=5", headers=AUTH).json()
    assert a["verified"]
    assert a["total"] > 5


def test_simulate_halts_on_gpu_ceiling(client):
    spec = {
        "run_id": "sim-2",
        "scenario": "independent",
        "root_seed": 3,
        "steps": 3,
        "dataset_hash": H,
        "git_commit": "abcdef1",
        "config_hash": "c",
        "env_lock_hash": "e",
    }
    r = client.post(
        "/v1/runs/simulate", json={"spec": spec, "gpu_hours_per_step": 1000}, headers=AUTH
    )
    assert r.json()["outcome"] == "halt:gpu-hours-ceiling"


def test_unknown_fields_rejected(client):
    r = client.post(
        "/v1/governance/evaluate", json={"checkpoint": "step", "context": {}, "x": 1}, headers=AUTH
    )
    assert r.status_code == 422


def test_oversized_body_rejected(client):
    r = client.post("/v1/governance/evaluate", content=b"x" * (300 * 1024), headers=AUTH)
    assert r.status_code == 413


def test_console_is_served_with_csp(client):
    r = client.get("/console/")
    assert r.status_code == 200
    assert "Governance console" in r.text
    assert r.headers["Content-Security-Policy"] == (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
