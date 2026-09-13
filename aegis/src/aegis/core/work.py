"""Immutable repository inspection requests and explicit queue decisions."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class WorkRequest(BaseModel):
    """A bounded read-only workflow; never shell commands or arbitrary destinations."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    repository: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$"
    )
    purpose: str = Field(min_length=3, max_length=500)
    request_key: str = Field(pattern=r"^[A-Za-z0-9_-]{16,80}$")


class WorkDecision(BaseModel):
    """A reviewer decision against the exact persisted revision."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: Literal["approved", "rejected"]
    expected_revision: int = Field(ge=0, strict=True)
    reason: str = Field(min_length=3, max_length=500)


class InspectionReport(BaseModel):
    """Selected GitHub metadata, not a code audit or security certification."""

    model_config = ConfigDict(extra="forbid")
    repository: str
    default_branch: str = Field(min_length=1, max_length=255)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    archived: bool
    visibility: str
    open_issues: int = Field(ge=0)
    observation: str = (
        "Repository metadata only; source code and security controls were not audited."
    )


class WorkItem(BaseModel):
    """Persisted request, attribution, decision and final report."""

    model_config = ConfigDict(extra="forbid")
    id: str
    tenant: str
    requested_by: str
    request: WorkRequest
    status: Literal["pending", "approved", "rejected", "running", "succeeded", "failed"] = "pending"
    revision: int = 0
    created_at: int
    updated_at: int
    reviewer: str | None = None
    decision_reason: str | None = None
    approval_expires_at: int | None = None
    result: InspectionReport | None = None
    error: str | None = None
