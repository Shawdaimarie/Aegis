"""FastAPI application factory for the Aegis v1 control plane."""

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from aegis import __version__
from aegis.adapters.secrets import get_secret
from aegis.api.v1.security import Principal as ApiPrincipal
from aegis.api.v1.security import new_request_id, require_principal
from aegis.core.errors import ConfigurationError, GovernanceViolationError, IntegrityError
from aegis.core.types import Checkpoint, RunContext
from aegis.governance.audit import AuditLog
from aegis.governance.engine import PolicyEngine
from aegis.governance.loader import load_boundaries
from aegis.identity import (
    ApprovalRequest,
    AuthorizationRequest,
    CapabilityCodec,
    DelegateCapabilityRequest,
    IdentityControlPlane,
    InspectCapabilityRequest,
    IssueCapabilityRequest,
    RevokeCapabilityRequest,
)
from aegis.training.runner import Runner, RunSpec

MAX_BODY_BYTES = 256 * 1024
RATE_LIMIT_PER_MINUTE = 120
RATE_WINDOW_SECONDS = 60
Auth = Annotated[ApiPrincipal, Depends(require_principal)]


class EvaluateRequest(BaseModel):
    """Body for POST /v1/governance/evaluate."""

    model_config = ConfigDict(extra="forbid")

    checkpoint: Checkpoint
    context: RunContext


class SimulateRequest(BaseModel):
    """Body for POST /v1/runs/simulate."""

    model_config = ConfigDict(extra="forbid")

    spec: RunSpec
    loss_start: float = Field(gt=0, default=2.0)
    loss_decay: float = Field(gt=0, le=1, default=0.97)
    gpu_hours_per_step: float = Field(ge=0, default=0.01)


def _install_guard(app: FastAPI) -> None:
    """Attach body-size, rate-limit, and security-header middleware."""
    buckets: dict[str, deque[float]] = defaultdict(deque)

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Reject oversized bodies, rate-limit per client, and stamp security headers."""
        rid = new_request_id()
        length = int(request.headers.get("content-length") or 0)
        if length > MAX_BODY_BYTES:
            return JSONResponse({"error": "body too large", "request_id": rid}, status_code=413)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        q = buckets[client]
        while q and now - q[0] > RATE_WINDOW_SECONDS:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse({"error": "rate limited", "request_id": rid}, status_code=429)
        q.append(now)
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def create_app(
    governance_path: Path | None = None,
    *,
    capability_signing_key: str | None = None,
) -> FastAPI:
    """Build the API with immutable governance and identity control planes."""
    default_path = Path(__file__).resolve().parents[4] / "configs/governance/default.yaml"
    path = governance_path or default_path
    audit = AuditLog()
    engine = PolicyEngine(load_boundaries(path), audit)
    runner = Runner(engine)
    signing_key = capability_signing_key or get_secret("AEGIS_CAPABILITY_SIGNING_KEY")
    identity = IdentityControlPlane(CapabilityCodec(signing_key), audit)
    app = FastAPI(
        title="Aegis Platform API",
        version=__version__,
        openapi_version="3.1.0",
        docs_url="/v1/docs",
        openapi_url="/v1/openapi.json",
    )
    app.state.identity_control_plane = identity
    app.state.audit_log = audit

    _install_guard(app)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness probe."""
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        """Platform and API version."""
        return {"version": __version__, "api": "v1"}

    @app.get("/v1/governance/boundaries")
    async def boundaries(_: Auth) -> list[dict[str, object]]:
        """Return the immutable boundary set currently enforced."""
        return [b.model_dump(mode="json") for b in engine.boundaries]

    @app.post("/v1/governance/evaluate")
    async def evaluate(body: EvaluateRequest, principal: Auth) -> dict[str, object]:
        """Evaluate a run snapshot at one checkpoint without mutating a run."""
        decision = engine.evaluate(body.checkpoint, body.context, raise_on_block=False)
        audit.append(principal.subject, "api:evaluate", f"run:{body.context.run_id}", "ok")
        return {
            "checkpoint": decision.checkpoint,
            "allowed": decision.allowed,
            "advisories": list(decision.advisories),
            "blocked_by": decision.blocked_by,
            "halted_by": decision.halted_by,
        }

    @app.post("/v1/runs/simulate", status_code=status.HTTP_201_CREATED)
    async def simulate(body: SimulateRequest, principal: Auth) -> dict[str, object]:
        """Execute a synthetic run under governance and return its manifest."""

        def step(index: int, _: object) -> dict[str, float]:
            """Produce deterministic synthetic metrics for API validation."""
            return {
                "loss": body.loss_start * (body.loss_decay**index),
                "res:gpu_hours": body.gpu_hours_per_step * index,
            }

        try:
            manifest = runner.run(body.spec, step)
            outcome = "completed"
        except GovernanceViolationError as exc:
            manifest = exc.manifest  # type: ignore[attr-defined]
            outcome = f"{exc.severity.lower()}:{exc.boundary_id}"
        except ConfigurationError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        audit.append(principal.subject, "api:simulate", f"run:{body.spec.run_id}", outcome)
        return {
            "outcome": outcome,
            "manifest": manifest.model_dump(mode="json"),
            "manifest_id": manifest.manifest_id,
        }

    @app.post("/v1/identity/capabilities", status_code=status.HTTP_201_CREATED)
    async def issue_capability(body: IssueCapabilityRequest, principal: Auth) -> dict[str, object]:
        """Issue a short-lived root capability through the administrative API."""
        try:
            issued = identity.issue(body)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        audit.append(
            principal.subject,
            "api:capability:issue",
            f"capability:{issued.grant.capability_id}",
            "ok",
        )
        return issued.model_dump(mode="json")

    @app.post("/v1/identity/capabilities/delegate", status_code=status.HTTP_201_CREATED)
    async def delegate_capability(
        body: DelegateCapabilityRequest, principal: Auth
    ) -> dict[str, object]:
        """Issue a strictly narrower delegated capability."""
        try:
            issued = identity.delegate(body)
        except (IntegrityError, ValueError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        audit.append(
            principal.subject,
            "api:capability:delegate",
            f"capability:{issued.grant.capability_id}",
            "ok",
        )
        return issued.model_dump(mode="json")

    @app.post("/v1/identity/capabilities/inspect")
    async def inspect_capability(
        body: InspectCapabilityRequest, principal: Auth
    ) -> dict[str, object]:
        """Validate and decode a capability without consuming it."""
        try:
            grant = identity.inspect(body.token)
        except IntegrityError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        audit.append(
            principal.subject,
            "api:capability:inspect",
            f"capability:{grant.capability_id}",
            "ok",
        )
        return grant.model_dump(mode="json")

    @app.post("/v1/identity/approvals", status_code=status.HTTP_201_CREATED)
    async def approve_capability(body: ApprovalRequest, principal: Auth) -> dict[str, object]:
        """Create a human approval bound to one exact authorization intent."""
        try:
            approval = identity.approve(body)
        except (IntegrityError, ValueError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        audit.append(
            principal.subject,
            "api:capability:approve",
            f"capability:{approval.capability_id}",
            "ok",
        )
        return approval.model_dump(mode="json")

    @app.post("/v1/identity/revocations", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_capability(body: RevokeCapabilityRequest, principal: Auth) -> Response:
        """Revoke a capability and its registered descendants."""
        identity.revoke(body)
        audit.append(
            principal.subject,
            "api:capability:revoke",
            f"capability:{body.capability_id}",
            "ok",
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/v1/authorization/check")
    async def authorize(body: AuthorizationRequest, principal: Auth) -> dict[str, object]:
        """Evaluate and consume a capability when the request is allowed."""
        decision = identity.authorize(body)
        audit.append(
            principal.subject,
            "api:authorization:check",
            f"request:{body.request_id}",
            "allow" if decision.allowed else "deny",
            {"reason": decision.reason.value},
        )
        return decision.model_dump(mode="json")

    @app.get("/v1/audit")
    async def audit_tail(_: Auth, limit: int = 50) -> dict[str, object]:
        """Verify the chain and return the most recent records."""
        limit = max(1, min(limit, 500))
        audit.verify()
        records = list(audit)[-limit:]
        return {
            "total": len(audit),
            "verified": True,
            "records": [r.model_dump(mode="json") for r in records],
        }

    web = Path(__file__).resolve().parents[4] / "web"
    if web.is_dir():
        app.mount("/console", StaticFiles(directory=web, html=True), name="console")
    return app
