"""FastAPI application factory for the Aegis v1 control plane."""

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from aegis import __version__
from aegis.adapters.authorization_store import SQLiteAuthorizationStore
from aegis.adapters.secrets import get_secret
from aegis.api.v1.controls import control_store, install_control_routes
from aegis.api.v1.reviews import install_review_routes
from aegis.api.v1.security import Principal as ApiPrincipal
from aegis.api.v1.security import new_request_id, require_approver, require_principal
from aegis.core.errors import (
    ConfigurationError,
    GovernanceViolationError,
    IntegrityError,
    StateUnavailableError,
)
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
MAX_RATE_BUCKETS = 4096
Auth = Annotated[ApiPrincipal, Depends(require_principal)]
HumanAuth = Annotated[ApiPrincipal, Depends(require_approver)]


class SimulationSpec(RunSpec):
    """Server-owned limits; callers cannot suppress per-step governance."""

    steps: int = Field(ge=1, le=1000)
    governance_cadence: Literal[1] = 1


class EvaluateRequest(BaseModel):
    """Body for POST /v1/governance/evaluate."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    checkpoint: Checkpoint
    context: RunContext


class SimulateRequest(BaseModel):
    """Body for POST /v1/runs/simulate."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    spec: SimulationSpec
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
        try:
            length = int(request.headers.get("content-length") or 0)
            if length < 0:
                raise ValueError
        except ValueError:
            return JSONResponse(
                {"error": "invalid content length", "request_id": rid}, status_code=400
            )
        if length > MAX_BODY_BYTES:
            return JSONResponse({"error": "body too large", "request_id": rid}, status_code=413)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                return JSONResponse({"error": "body too large", "request_id": rid}, status_code=413)
            body.extend(chunk)
        # Starlette's middleware replays the cached body to the downstream parser.
        request._body = bytes(body)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        for key in list(buckets):
            if not buckets[key] or now - buckets[key][-1] > RATE_WINDOW_SECONDS:
                del buckets[key]
        if client not in buckets and len(buckets) >= MAX_RATE_BUCKETS:
            return JSONResponse(
                {"error": "rate capacity reached", "request_id": rid}, status_code=429
            )
        q = buckets[client]
        while q and now - q[0] > RATE_WINDOW_SECONDS:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse({"error": "rate limited", "request_id": rid}, status_code=429)
        q.append(now)
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        if request.url.path.startswith(("/v1/controls", "/v1/reviews", "/console")):
            response.headers["Content-Security-Policy"] += (
                "; frame-ancestors 'none'; base-uri 'none'"
            )
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def _durable_identity(audit: AuditLog, signing_key: str) -> IdentityControlPlane:
    """Bind API issuance and authorization to an explicitly provisioned ledger."""
    ledger_path = Path(get_secret("AEGIS_AUTHORIZATION_DB_PATH"))
    if ledger_path.resolve() == Path(get_secret("AEGIS_CONTROL_DB_PATH")).resolve():
        raise ConfigurationError("authorization and control databases must be separate files")
    return IdentityControlPlane(
        CapabilityCodec(signing_key), audit, state=SQLiteAuthorizationStore(ledger_path)
    )


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
    identity = _durable_identity(audit, signing_key)
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

    @app.exception_handler(StateUnavailableError)
    async def unavailable_state(_: Request, __: StateUnavailableError) -> JSONResponse:
        """Never expose database paths or authorize against unavailable state."""
        return JSONResponse({"detail": "authorization state unavailable"}, status_code=503)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        """Return validation errors without reflecting secrets or non-finite inputs."""
        return JSONResponse(
            {
                "detail": [
                    {"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()
                ]
            },
            status_code=422,
        )

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

    _install_identity_routes(app, identity, audit)
    install_control_routes(app)

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


def _install_identity_routes(app: FastAPI, identity: IdentityControlPlane, audit: AuditLog) -> None:
    """Install administrative routes with a separate authenticated human approval path."""
    install_review_routes(app, identity)

    @app.post("/v1/identity/capabilities", status_code=status.HTTP_201_CREATED)
    async def issue_capability(body: IssueCapabilityRequest, principal: Auth) -> dict[str, object]:
        """Issue a short-lived root capability through the administrative API."""
        if body.issuer.id != principal.subject or body.issuer.kind.value != "service":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "issuer identity mismatch")
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
    async def approve_capability(body: ApprovalRequest, principal: HumanAuth) -> dict[str, object]:
        """Create a human approval bound to one exact authorization intent."""
        if body.approver.id != principal.subject or body.approver.tenant != principal.tenant:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "approver identity mismatch")
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
        if body.revoked_by.id != principal.subject or body.revoked_by.kind.value != "service":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "revoker identity mismatch")
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
        with control_store() as store, store.decision_settings(body.tenant) as controls:
            decision = identity.authorize(
                body,
                automation_enabled=controls.automation_enabled,
                require_human_approval=controls.require_human_approval,
            )
        audit.append(
            principal.subject,
            "api:authorization:check",
            f"request:{body.request_id}",
            "allow" if decision.allowed else "deny",
            {"reason": decision.reason.value},
        )
        return decision.model_dump(mode="json")
