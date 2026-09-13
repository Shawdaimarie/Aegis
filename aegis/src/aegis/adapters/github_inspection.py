"""Fixed-host, read-only GitHub metadata inspection; never execute repository content."""

import http.client
import json
import re
from http import HTTPStatus
from urllib.parse import quote

from aegis.core.work import InspectionReport

MAX_BRANCH_LENGTH = 255
MAX_RESPONSE_BYTES = 1024 * 1024


def github_get(path: str, token: str) -> dict[str, object]:
    """Perform one bounded HTTPS GET without redirects, retries or caller-selected hosts."""
    connection = http.client.HTTPSConnection("api.github.com", timeout=10)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Sentinal-inspection",
                "X-GitHub-Api-Version": "2026-03-10",
                "Authorization": "Bearer " + token,
            },
        )
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != HTTPStatus.OK or len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("GitHub response unavailable")
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise ValueError("unexpected GitHub response")
        return parsed
    finally:
        connection.close()


def inspect_repository(repository: str, token: str) -> InspectionReport:
    """Capture repository identity and the observed default-branch commit."""
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", repository
    ):
        raise ValueError("invalid repository")
    path = "/repos/" + repository
    metadata = github_get(path, token)
    name, branch = metadata.get("full_name"), metadata.get("default_branch")
    if not isinstance(name, str) or name.lower() != repository.lower():
        raise ValueError("repository identity mismatch")
    if not isinstance(branch, str) or not 0 < len(branch) <= MAX_BRANCH_LENGTH:
        raise ValueError("invalid default branch")
    commit = github_get(path + "/commits/" + quote(branch, safe=""), token)
    return InspectionReport.model_validate(
        {
            "repository": name,
            "default_branch": branch,
            "commit_sha": commit.get("sha"),
            "archived": metadata.get("archived"),
            "visibility": metadata.get("visibility"),
            "open_issues": metadata.get("open_issues_count"),
        }
    )
