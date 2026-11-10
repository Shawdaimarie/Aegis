"""FastAPI application factory for v1."""

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
from aegis.api.v1.security import Principal, new_request_id, require_principal
from aegis.core.errors import ConfigurationError, GovernanceViolationError
from aegis.core.types import Checkpoint, RunContext
from aegis.governance.audit import AuditLog
from aegis.governance.engine import PolicyEngine
from aegis.governance.loader import load_boundaries
from aegis.training.runner import Runner, RunSpec

MAX_BODY_BYTES = 256 * 1024
RATE_LIMIT_PER_MINUTE = 120
RATE_WINDOW_SECONDS = 60
Auth = Annotated[Principal, Depends(require_principal)]


class EvaluateRequest(BaseModel):
    """Body for POST /v1/governance/evaluate."""

    model_config = ConfigDict(extra="forbid")

    checkpoint: Checkpoint
    context: RunContext


class SimulateRequest(BaseModel):
    """Body for POST /v1/runs/simulate: a synthetic run for validating governance end-to-end."""

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


def create_app(governance_path: Path | None = None) -> FastAPI:
    """Build the application with a read-only boundary set."""
    path = (
        governance_path or Path(__file__).resolve().parents[4] / "configs/governance/default.yaml"
    )
    audit = AuditLog()
    engine = PolicyEngine(load_boundaries(path), audit)
    runner = Runner(engine)
    app = FastAPI(
        title="Aegis Platform API",
        version=__version__,
        docs_url="/v1/docs",
        openapi_url="/v1/openapi.json",
    )

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
        """The immutable boundary set currently enforced."""
        return [b.model_dump(mode="json") for b in engine.boundaries]

    @app.post("/v1/governance/evaluate")
    async def evaluate(body: EvaluateRequest, principal: Auth) -> dict[str, object]:
        """Evaluate a run snapshot at one checkpoint; never mutates any run."""
        d = engine.evaluate(body.checkpoint, body.context, raise_on_block=False)
        audit.append(principal.subject, "api:evaluate", f"run:{body.context.run_id}", "ok")
        return {
            "checkpoint": d.checkpoint,
            "allowed": d.allowed,
            "advisories": list(d.advisories),
            "blocked_by": d.blocked_by,
            "halted_by": d.halted_by,
        }

    @app.post("/v1/runs/simulate", status_code=status.HTTP_201_CREATED)
    async def simulate(body: SimulateRequest, principal: Auth) -> dict[str, object]:
        """Execute a synthetic run under governance and return its manifest."""

        def step(i: int, _: object) -> dict[str, float]:
            """Geometric loss decay with linear GPU-hour accrual."""
            return {
                "loss": body.loss_start * (body.loss_decay**i),
                "res:gpu_hours": body.gpu_hours_per_step * i,
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
