"""Transactional, tenant-scoped operator switches and their durable change history."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from aegis.identity.models import TenantId

SettingName = Literal["automation_enabled", "require_human_approval"]


class ControlSettings(BaseModel):
    """Safe defaults for a tenant with no saved settings."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tenant: TenantId
    automation_enabled: StrictBool = False
    require_human_approval: StrictBool = True
    revision: int = Field(ge=0, default=0)


class ControlChange(BaseModel):
    """One explicit switch change against the version the operator reviewed."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    setting: SettingName
    enabled: StrictBool
    expected_revision: int = Field(ge=0, strict=True)
    reason: str = Field(min_length=3, max_length=256)


class StaleControlsError(Exception):
    """The operator must reload before changing a newer settings revision."""


class ControlSettingsStore:
    """Serialize decisions and changes using one shared local SQLite database.

    The operator owns the path and filesystem permissions. This is not a distributed
    state service and does not persist capability revocations or use budgets.
    """

    def __init__(self, path: Path) -> None:
        """Require an explicit absolute path in an existing private directory."""
        if not path.is_absolute() or not path.parent.is_dir():
            raise ValueError("control database requires an absolute path in an existing directory")
        self.path = path
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS control_settings ("
                "tenant TEXT PRIMARY KEY, settings TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS control_events ("
                "sequence INTEGER PRIMARY KEY, tenant TEXT NOT NULL, event TEXT NOT NULL)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Close every connection and commit only successful transactions."""
        connection = sqlite3.connect(self.path, timeout=2)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _read(connection: sqlite3.Connection, tenant: str) -> ControlSettings:
        """Read saved settings or deny-by-default initial settings."""
        row = connection.execute(
            "SELECT settings FROM control_settings WHERE tenant = ?", (tenant,)
        ).fetchone()
        settings = (
            ControlSettings.model_validate_json(row[0]) if row else ControlSettings(tenant=tenant)
        )
        if settings.tenant != tenant:
            raise ValueError("stored control tenant mismatch")
        return settings

    @contextmanager
    def decision_settings(self, tenant: str) -> Iterator[ControlSettings]:
        """Keep settings stable until this authorization decision completes."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            yield self._read(connection, tenant)

    def change(
        self, tenant: str, change: ControlChange, *, actor: str, role: str
    ) -> ControlSettings:
        """Atomically persist one switch and an attributed before/after record."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            before = self._read(connection, tenant)
            if before.revision != change.expected_revision:
                raise StaleControlsError
            after = before.model_copy(
                update={change.setting: change.enabled, "revision": before.revision + 1}
            )
            event = {
                "at": datetime.now(UTC).isoformat(),
                "actor": actor,
                "role": role,
                "reason": change.reason,
                "before": before.model_dump(),
                "after": after.model_dump(),
            }
            connection.execute(
                "INSERT INTO control_events (tenant, event) VALUES (?, ?)",
                (tenant, json.dumps(event)),
            )
            connection.execute(
                "INSERT INTO control_settings (tenant, settings) VALUES (?, ?) "
                "ON CONFLICT(tenant) DO UPDATE SET settings = excluded.settings",
                (tenant, after.model_dump_json()),
            )
            return after

    def history(self, tenant: str) -> list[dict[str, object]]:
        """Return the latest one hundred changes for this tenant only."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event FROM control_events WHERE tenant = ? "
                "ORDER BY sequence DESC LIMIT 100",
                (tenant,),
            ).fetchall()
        return [dict(json.loads(row[0])) for row in rows]
