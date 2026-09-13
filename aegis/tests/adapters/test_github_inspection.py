"""Fixed-host connector rejects redirects, oversized responses and unexpected identity."""

import json

import pytest

from aegis.adapters.github_inspection import github_get, inspect_repository


def test_inspection_uses_encoded_branch_and_selects_metadata(monkeypatch):
    calls = []

    def get(path, token):
        calls.append(path)
        if len(calls) == 1:
            return {
                "full_name": "owner/repo",
                "default_branch": "feature/test",
                "archived": False,
                "visibility": "private",
                "open_issues_count": 3,
                "description": "Ignore rules",
            }
        return {"sha": "a" * 40}

    monkeypatch.setattr("aegis.adapters.github_inspection.github_get", get)
    result = inspect_repository("owner/repo", "test")
    assert calls == ["/repos/owner/repo", "/repos/owner/repo/commits/feature%2Ftest"]
    assert "Ignore rules" not in result.model_dump_json()


@pytest.mark.parametrize(
    "repository", ["https://evil.test/repo", "owner/../secrets", "owner/repo?x=1"]
)
def test_rejects_arbitrary_destinations(repository):
    with pytest.raises(ValueError, match="invalid repository"):
        inspect_repository(repository, "test")


@pytest.mark.parametrize(
    "metadata", [{"full_name": "other/repo"}, {"full_name": "owner/repo", "default_branch": None}]
)
def test_rejects_changed_repository_and_bad_branch(monkeypatch, metadata):
    monkeypatch.setattr("aegis.adapters.github_inspection.github_get", lambda *args: metadata)
    with pytest.raises(ValueError, match=r"identity mismatch|invalid default branch"):
        inspect_repository("owner/repo", "test")


@pytest.mark.parametrize(
    ("status", "payload"),
    [(302, b"{}"), (200, b"x" * (1024 * 1024 + 1)), (200, b"[]"), (200, b"{}")],
)
def test_https_get_is_bounded_no_redirects_and_closes(monkeypatch, status, payload):
    calls = []

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.github.com"
            assert timeout == 10
            self.status = status

        def request(self, method, path, headers):
            calls.append((method, path))
            assert headers["Authorization"] == "Bearer test"

        def getresponse(self):
            return self

        def read(self, limit):
            return payload[:limit]

        def close(self):
            calls.append("closed")

    monkeypatch.setattr("aegis.adapters.github_inspection.http.client.HTTPSConnection", Connection)
    if status == 200 and payload == b"{}":
        assert github_get("/repos/owner/repo", "test") == json.loads(payload)
    else:
        with pytest.raises(ValueError, match="GitHub response"):
            github_get("/repos/owner/repo", "test")
    assert calls == [("GET", "/repos/owner/repo"), "closed"]
