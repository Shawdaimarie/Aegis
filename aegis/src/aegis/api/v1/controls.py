"""Authenticate named control operators and expose two independent switches."""

import hashlib
import hmac
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from aegis.adapters.control_settings import (
    ControlChange,
    ControlSettingsStore,
    SettingName,
    StaleControlsError,
)
from aegis.adapters.secrets import get_secret
from aegis.core.errors import ConfigurationError
from aegis.identity.models import Identifier, TenantId


class ControlOperator(BaseModel):
    """Operator-owned identity and permissions, never populated from request claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    subject: Identifier
    tenant: TenantId
    role: Literal["admin", "user", "authorized_personnel"]
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    permissions: tuple[SettingName, ...] = ()

    def allowed_settings(self) -> tuple[SettingName, ...]:
        """Admins manage both switches within their own tenant."""
        if self.role == "admin":
            return ("automation_enabled", "require_human_approval")
        return self.permissions


def require_control_operator(authorization: str | None = Header(default=None)) -> ControlOperator:
    """Map a distinct operator credential to one trusted server-side identity."""
    try:
        operators = TypeAdapter(list[ControlOperator]).validate_json(
            get_secret("AEGIS_CONTROL_OPERATORS")
        )
        hashes = [operator.token_sha256 for operator in operators]
        excluded = {
            hashlib.sha256(get_secret(name).encode()).hexdigest() for name in ("AEGIS_API_TOKEN",)
        }
        # The reviewer credential must not silently acquire switch-management authority.
        if reviewer := os.environ.get("AEGIS_APPROVER_TOKEN"):
            excluded.add(hashlib.sha256(reviewer.encode()).hexdigest())
        if not operators or len(set(hashes)) != len(hashes) or excluded.intersection(hashes):
            raise ValueError("invalid operator credential mapping")
    except (ConfigurationError, ValueError) as exc:
        raise HTTPException(503, "control operator configuration unavailable") from exc
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing control credential")
    supplied = authorization.removeprefix("Bearer ").strip()
    digest = hashlib.sha256(supplied.encode()).hexdigest()
    for operator in operators:
        if hmac.compare_digest(digest, operator.token_sha256):
            return operator
    raise HTTPException(401, "invalid control credential")


@contextmanager
def control_store() -> Iterator[ControlSettingsStore]:
    """Fail closed on missing configuration, corrupt data or unavailable storage."""
    try:
        store = ControlSettingsStore(Path(get_secret("AEGIS_CONTROL_DB_PATH")))
        yield store
    except StaleControlsError as exc:
        raise HTTPException(409, "settings changed; refresh and review before retrying") from exc
    except (ConfigurationError, ValueError, sqlite3.Error, OSError) as exc:
        raise HTTPException(503, "control settings unavailable; automation is blocked") from exc


OperatorAuth = Annotated[ControlOperator, Depends(require_control_operator)]


def install_control_routes(app: FastAPI) -> None:
    """Install tenant-scoped read, update and audit endpoints."""

    @app.get("/v1/controls")
    def read_controls(operator: OperatorAuth) -> dict[str, object]:
        """Return current persisted switches and the caller's actual permissions."""
        with control_store() as store, store.decision_settings(operator.tenant) as settings:
            return {
                "settings": settings.model_dump(),
                "subject": operator.subject,
                "role": operator.role,
                "permissions": operator.allowed_settings(),
            }

    @app.patch("/v1/controls")
    def change_controls(change: ControlChange, operator: OperatorAuth) -> dict[str, object]:
        """Change exactly one permitted switch and retain the attributed audit event."""
        if change.setting not in operator.allowed_settings():
            raise HTTPException(403, "not authorized to change this control")
        with control_store() as store:
            settings = store.change(
                operator.tenant, change, actor=operator.subject, role=operator.role
            )
        return {
            "settings": settings.model_dump(),
            "subject": operator.subject,
            "role": operator.role,
            "permissions": operator.allowed_settings(),
        }

    @app.get("/v1/controls/history")
    def control_history(operator: OperatorAuth) -> list[dict[str, object]]:
        """Show durable switch changes for the authenticated tenant."""
        with control_store() as store:
            return store.history(operator.tenant)
