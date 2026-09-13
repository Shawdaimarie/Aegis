"""Persistence, human authority and real connector boundaries for queued inspections."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from aegis.adapters.work_queue import WorkConflictError, WorkQueue, initialize_database
from aegis.api.v1.app import create_app
from aegis.core.errors import StateUnavailableError
from aegis.core.work import InspectionReport, WorkDecision, WorkRequest
from tests.api.test_controls import ADMIN, OTHER, operator
from tests.api.test_identity_v1 import REVIEWER

REQUEST = {
    "repository": "Shawdaimarie/Aegis",
    "purpose": "Review repository baseline",
    "request_key": "unique-request-0001",
}
REPORT = InspectionReport(
    repository="Shawdaimarie/Aegis",
    default_branch="main",
    commit_sha="a" * 40,
    archived=False,
    visibility="private",
    open_issues=2,
)


@pytest.fixture
def work_setup(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_API_TOKEN", "test-token")
    monkeypatch.setenv("AEGIS_CAPABILITY_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", "separate-human-test-key")
    monkeypatch.setenv("AEGIS_APPROVER_SUBJECT", "human:reviewer")
    monkeypatch.setenv("AEGIS_APPROVER_TENANT", "acme")
    operators = [
        operator("human:operator", "local-admin-control-secret"),
        operator("human:other", "local-other-control-secret", tenant="other"),
    ]
    for entry in operators:
        entry["workflows"] = ["github.inspect"]
    monkeypatch.setenv("AEGIS_CONTROL_OPERATORS", json.dumps(operators))
    monkeypatch.setenv("AEGIS_GITHUB_REPOSITORIES", json.dumps({"acme": [REQUEST["repository"]]}))
    monkeypatch.setenv("AEGIS_GITHUB_READ_TOKEN", "disposable-connector-key")
    path = tmp_path / "work.sqlite3"
    initialize_database(path)
    monkeypatch.setenv("AEGIS_WORK_DB_PATH", str(path))
    calls = []

    def inspect(repo, token):
        calls.append((repo, token))
        return REPORT

    monkeypatch.setattr("aegis.api.v1.work.inspect_repository", inspect)
    client = TestClient(create_app())
    client.patch(
        "/v1/controls",
        headers=ADMIN,
        json={
            "setting": "automation_enabled",
            "enabled": True,
            "expected_revision": 0,
            "reason": "Run controlled test",
        },
    )
    return client, path, calls


def submit(client):
    response = client.post("/v1/work/jobs", json=REQUEST, headers=ADMIN)
    assert response.status_code == 201
    return response.json()


def decide(client, item, decision="approved"):
    return client.post(
        f"/v1/work/jobs/{item['id']}/decision",
        headers=REVIEWER,
        json={
            "decision": decision,
            "expected_revision": item["revision"],
            "reason": "Reviewed exact repository and purpose",
        },
    )


def test_queue_restart_approval_result_and_duplicate_run(work_setup):
    client, path, calls = work_setup
    item = submit(client)
    assert submit(client)["id"] == item["id"]
    assert not calls
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN).status_code == 409
    assert decide(client, item).status_code == 200
    client = TestClient(create_app())
    assert (
        client.get("/v1/work/reviewer/jobs", headers=REVIEWER).json()[0]["reviewer"]
        == "human:reviewer"
    )
    result = client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN)
    assert result.status_code == 200
    assert result.json()["result"]["commit_sha"] == "a" * 40
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN).status_code == 409
    assert len(calls) == 1
    assert WorkQueue(path).list_items("acme")[0].status == "succeeded"
    with WorkQueue(path).transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


def test_tenant_identity_policy_and_reviewer_separation(work_setup):
    client, _, calls = work_setup
    item = submit(client)
    assert client.get("/v1/work/operator/jobs", headers=OTHER).json() == []
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=OTHER).status_code == 404
    assert (
        client.post(
            f"/v1/work/jobs/{item['id']}/decision",
            headers=ADMIN,
            json={"decision": "approved", "reason": "Not a reviewer", "expected_revision": 0},
        ).status_code
        == 401
    )
    assert (
        client.post("/v1/work/jobs", headers=ADMIN, json={**REQUEST, "tenant": "other"}).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/work/jobs", headers=ADMIN, json={**REQUEST, "repository": "unapproved/repo"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/work/jobs", headers=ADMIN, json={**REQUEST, "purpose": "Different intent"}
        ).status_code
        == 409
    )
    assert not calls


def test_revoked_queue_decision_and_stale_revision(work_setup):
    client, _, calls = work_setup
    item = submit(client)
    approved = decide(client, item).json()
    assert decide(client, item).status_code == 409
    assert decide(client, approved, "rejected").status_code == 200
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN).status_code == 409
    assert not calls


def test_pause_and_removed_allowlist_block_before_network(work_setup, monkeypatch):
    client, _, calls = work_setup
    item = submit(client)
    decide(client, item)
    client.patch(
        "/v1/controls",
        headers=ADMIN,
        json={
            "setting": "automation_enabled",
            "enabled": False,
            "expected_revision": 1,
            "reason": "Pause before execution",
        },
    )
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN).status_code == 403
    monkeypatch.setenv("AEGIS_GITHUB_REPOSITORIES", "{}")
    assert client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN).status_code == 403
    assert not calls


def test_missing_config_permissions_storage_and_upstream_failure(work_setup, monkeypatch):
    client, path, _ = work_setup
    item = submit(client)
    decide(client, item)

    def fail(*args):
        raise ValueError("upstream credential must never be returned")

    monkeypatch.setattr("aegis.api.v1.work.inspect_repository", fail)
    result = client.post(f"/v1/work/jobs/{item['id']}/run", headers=ADMIN)
    assert result.json()["status"] == "failed"
    assert "upstream credential" not in result.text
    monkeypatch.setenv(
        "AEGIS_CONTROL_OPERATORS",
        json.dumps([operator("human:operator", "local-admin-control-secret")]),
    )
    assert client.get("/v1/work/operator/jobs", headers=ADMIN).status_code == 403
    monkeypatch.delenv("AEGIS_WORK_DB_PATH")
    assert client.get("/v1/work/reviewer/jobs", headers=REVIEWER).status_code == 503
    monkeypatch.setenv("AEGIS_WORK_DB_PATH", str(path))
    path.unlink()
    assert client.get("/v1/work/reviewer/jobs", headers=REVIEWER).status_code == 503
    assert not path.exists()


def test_parallel_claims_and_expiry(work_setup, monkeypatch):
    client, path, _ = work_setup
    item = submit(client)
    approved = decide(client, item).json()

    def claim(_):
        try:
            return WorkQueue(path).claim("acme", "human:operator", item["id"]).status
        except WorkConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(claim, range(8))).count("running") == 1
    queue = WorkQueue(path)
    second = queue.submit(
        "acme", "human:operator", WorkRequest(**{**REQUEST, "request_key": "unique-request-0002"})
    )
    queue.decide(
        "acme",
        "human:reviewer",
        second.id,
        WorkDecision(decision="approved", expected_revision=0, reason="Review second request"),
    )
    monkeypatch.setattr(
        "aegis.adapters.work_queue.time.time", lambda: approved["approval_expires_at"] + 1000
    )
    with pytest.raises(WorkConflictError):
        queue.claim("acme", "human:operator", second.id)


def test_initializer_and_corruption(work_setup):
    _, path, _ = work_setup
    with pytest.raises(FileExistsError):
        initialize_database(path)
    with pytest.raises(ValueError, match="absolute path"):
        initialize_database(path.parent / "missing" / "queue.db")
    queue = WorkQueue(path)
    item = queue.submit("acme", "human:operator", WorkRequest(**REQUEST))
    with queue.transaction() as conn:
        conn.execute("UPDATE jobs SET body=? WHERE id=?", ("{}", item.id))
    with pytest.raises(StateUnavailableError):
        queue.list_items("acme")
