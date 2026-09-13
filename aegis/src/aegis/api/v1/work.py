"""Human-approved, tenant-scoped read-only repository work."""

import http.client
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter

from aegis.adapters.github_inspection import inspect_repository
from aegis.adapters.secrets import get_secret
from aegis.adapters.work_queue import WorkConflictError, WorkQueue
from aegis.api.v1.controls import OperatorAuth, control_store
from aegis.api.v1.reviews import Reviewer
from aegis.core.errors import ConfigurationError
from aegis.core.work import WorkDecision, WorkItem, WorkRequest


def require_queue() -> WorkQueue:
    """Require separately provisioned storage; absent configuration disables this feature."""
    try:
        path = Path(get_secret("AEGIS_WORK_DB_PATH"))
        others = ("AEGIS_CONTROL_DB_PATH", "AEGIS_AUTHORIZATION_DB_PATH")
        if any(path.resolve() == Path(get_secret(name)).resolve() for name in others):
            raise ConfigurationError("queue storage must be separate")
        return WorkQueue(path)
    except ConfigurationError as exc:
        raise HTTPException(503, "work queue is not configured") from exc


def allowed_repository(tenant: str, repository: str) -> None:
    """Apply a trusted per-tenant repository allowlist at submission and execution."""
    try:
        allowed = TypeAdapter(dict[str, list[str]]).validate_json(
            get_secret("AEGIS_GITHUB_REPOSITORIES")
        )
    except (ConfigurationError, ValueError) as exc:
        raise HTTPException(503, "repository policy unavailable") from exc
    if repository.lower() not in {name.lower() for name in allowed.get(tenant, [])}:
        raise HTTPException(403, "repository is not allowed for this tenant")


Queue = Annotated[WorkQueue, Depends(require_queue)]


def install_work_routes(app: FastAPI) -> None:
    """Install explicit submission, review and execution with no autonomous worker."""

    @app.exception_handler(WorkConflictError)
    async def conflict_handler(_request: Request, _error: WorkConflictError) -> JSONResponse:
        """Expose a conflict without internal state or credentials."""
        return JSONResponse(
            {"detail": "work changed or expired; refresh before acting"}, status_code=409
        )

    @app.get("/v1/work/operator/jobs")
    def operator_jobs(operator: OperatorAuth, queue: Queue) -> list[WorkItem]:
        """List tenant work only for explicitly permitted workflow operators."""
        if "github.inspect" not in operator.workflows:
            raise HTTPException(403, "workflow permission required")
        return queue.list_items(operator.tenant)

    @app.get("/v1/work/reviewer/jobs")
    def reviewer_jobs(reviewer: Reviewer, queue: Queue) -> list[WorkItem]:
        """List the exact saved requests and results for the reviewer's tenant."""
        return queue.list_items(reviewer.tenant)

    @app.post("/v1/work/jobs", status_code=201)
    def submit(body: WorkRequest, operator: OperatorAuth, queue: Queue) -> WorkItem:
        """Save a new request without executing it or granting approval."""
        if "github.inspect" not in operator.workflows:
            raise HTTPException(403, "workflow permission required")
        allowed_repository(operator.tenant, body.repository)
        return queue.submit(operator.tenant, operator.subject, body)

    @app.post("/v1/work/jobs/{job_id}/decision")
    def decide(job_id: str, body: WorkDecision, reviewer: Reviewer, queue: Queue) -> WorkItem:
        """Record a decision against the immutable stored request and reviewed revision."""
        try:
            return queue.decide(reviewer.tenant, reviewer.subject, job_id, body)
        except LookupError as exc:
            raise HTTPException(404, "work not found") from exc

    @app.post("/v1/work/jobs/{job_id}/run")
    def run(job_id: str, operator: OperatorAuth, queue: Queue) -> WorkItem:
        """Claim once after policy checks, inspect GitHub and retain the final result."""
        if "github.inspect" not in operator.workflows:
            raise HTTPException(403, "workflow permission required")
        try:
            token = get_secret("AEGIS_GITHUB_READ_TOKEN")
        except ConfigurationError as exc:
            raise HTTPException(503, "GitHub connection unavailable") from exc
        try:
            with queue.transaction() as connection:
                item = queue.get(connection, operator.tenant, job_id)
            allowed_repository(operator.tenant, item.request.repository)
            with (
                control_store() as controls,
                controls.decision_settings(operator.tenant) as settings,
            ):
                if not settings.automation_enabled:
                    raise HTTPException(403, "automation is paused")
                item = queue.claim(operator.tenant, operator.subject, job_id)
        except LookupError as exc:
            raise HTTPException(404, "work not found") from exc
        try:
            report = inspect_repository(item.request.repository, token)
        except (OSError, ValueError, http.client.HTTPException):
            report = None
        return queue.finish(operator.tenant, operator.subject, job_id, report)
