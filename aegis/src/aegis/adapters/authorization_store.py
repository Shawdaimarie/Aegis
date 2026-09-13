"""Durable single-host authorization ledger with atomic budgets and revocation."""

from __future__ import annotations

import argparse
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from aegis.core.errors import StateUnavailableError
from aegis.identity.models import ApprovalGrant, DecisionReason
from aegis.identity.state import ConsumeRequest, ConsumeResult

SCHEMA_VERSION = 1
SCHEMA = (
    "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), "
    "version INTEGER NOT NULL, identity TEXT NOT NULL)",
    "CREATE TABLE capabilities (id TEXT PRIMARY KEY, max_uses INTEGER NOT NULL CHECK(max_uses>0), "
    "used INTEGER NOT NULL DEFAULT 0 CHECK(used>=0 AND used<=max_uses), "
    "parent TEXT REFERENCES capabilities(id))",
    "CREATE INDEX capability_parent ON capabilities(parent)",
    "CREATE TABLE revocations (id TEXT PRIMARY KEY, reason TEXT NOT NULL)",
    "CREATE TABLE approvals (id TEXT PRIMARY KEY, "
    "capability_id TEXT NOT NULL REFERENCES capabilities(id), "
    "body TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0 CHECK(used>=0))",
    "CREATE TABLE requests (id TEXT PRIMARY KEY, "
    "capability_id TEXT NOT NULL REFERENCES capabilities(id))",
)


def initialize_database(path: Path) -> None:
    """Create a new private ledger explicitly; never overwrite an existing path."""
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError("ledger requires an absolute path in an existing private directory")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    connection = sqlite3.connect(path)
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            for statement in SCHEMA:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO metadata VALUES (1, ?, ?)", (SCHEMA_VERSION, secrets.token_hex(16))
            )
    finally:
        connection.close()


class SQLiteAuthorizationStore:
    """Persist decisions across restarts and workers sharing one local database.

    Runtime access never creates a database or changes its schema. A new ledger
    cannot authorize capabilities absent from its issuance registry. Restoring
    an older backup still requires controlled recovery and signing-key rotation.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_request_ids: int = 100_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Bind an existing initialized ledger and remember its identity."""
        if not path.is_absolute() or max_request_ids < 1:
            raise StateUnavailableError("invalid authorization ledger configuration")
        self.path = path
        self._clock = clock
        self.max_request_ids = max_request_ids
        self._identity: str | None = None
        with self._transaction() as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise StateUnavailableError("authorization ledger integrity check failed")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize operations and translate storage failures into fail-closed errors."""
        connection: sqlite3.Connection | None = None
        try:
            if self.path.is_symlink():
                raise StateUnavailableError("authorization ledger must not be a symlink")
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT version, identity FROM metadata WHERE id=1"
                ).fetchone()
                if not row or row[0] != SCHEMA_VERSION or not isinstance(row[1], str) or not row[1]:
                    raise StateUnavailableError("authorization ledger schema unavailable")
                if self._identity is not None and row[1] != self._identity:
                    raise StateUnavailableError("authorization ledger was replaced")
                self._identity = row[1]
                yield connection
        except (sqlite3.Error, OSError) as exc:
            raise StateUnavailableError("authorization ledger unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _budget(connection: sqlite3.Connection, capability_id: str, max_uses: int) -> int:
        """Reject unknown capabilities and inconsistent budget records."""
        row = connection.execute(
            "SELECT max_uses, used FROM capabilities WHERE id=?", (capability_id,)
        ).fetchone()
        if (
            row is None
            or row[0] != max_uses
            or type(row[1]) is not int
            or not 0 <= row[1] <= max_uses
        ):
            raise StateUnavailableError("capability registration unavailable")
        return int(max_uses - row[1])

    @staticmethod
    def _revoked(connection: sqlite3.Connection, capability_id: str) -> bool:
        """Read a durable revocation marker inside the current transaction."""
        return (
            connection.execute("SELECT 1 FROM revocations WHERE id=?", (capability_id,)).fetchone()
            is not None
        )

    def register_capability(self, capability_id: str, max_uses: int) -> None:
        """Commit root issuance before any token can be returned to a caller."""
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO capabilities (id, max_uses) VALUES (?, ?)", (capability_id, max_uses)
            )

    def revoke(self, capability_id: str, reason: str) -> None:
        """Revoke the root and every registered descendant in one transaction."""
        with self._transaction() as connection:
            connection.execute(
                "WITH RECURSIVE descendants(id) AS (SELECT ? UNION "
                "SELECT capabilities.id FROM capabilities JOIN descendants "
                "ON capabilities.parent=descendants.id) "
                "INSERT OR IGNORE INTO revocations (id, reason) SELECT id, ? FROM descendants",
                (capability_id, reason),
            )

    def register_delegation(
        self,
        *,
        parent_capability_id: str,
        child_capability_id: str,
        reserved_uses: int,
        parent_max_uses: int,
    ) -> int:
        """Atomically reserve parent budget and persist the revocation relationship."""
        with self._transaction() as connection:
            if self._revoked(connection, parent_capability_id):
                raise ValueError("revoked capability cannot be delegated")
            remaining = self._budget(connection, parent_capability_id, parent_max_uses)
            if not 0 < reserved_uses <= remaining:
                raise ValueError("delegated use budget exceeds the parent remaining budget")
            connection.execute(
                "UPDATE capabilities SET used=used+? WHERE id=?",
                (reserved_uses, parent_capability_id),
            )
            connection.execute(
                "INSERT INTO capabilities (id, max_uses, parent) VALUES (?, ?, ?)",
                (child_capability_id, reserved_uses, parent_capability_id),
            )
            return remaining - reserved_uses

    def is_revoked(self, capability_id: str) -> bool:
        """Read persistent revocation state."""
        with self._transaction() as connection:
            return self._revoked(connection, capability_id)

    def remaining_uses(self, capability_id: str, max_uses: int) -> int:
        """Read the budget registered at issuance, never invent a fresh one."""
        with self._transaction() as connection:
            return self._budget(connection, capability_id, max_uses)

    def store_approval(self, approval: ApprovalGrant) -> None:
        """Persist the exact approval without resetting any existing use count."""
        with self._transaction() as connection:
            if self._revoked(connection, approval.capability_id):
                raise ValueError("cannot approve a revoked capability")
            connection.execute(
                "INSERT INTO approvals (id, capability_id, body) VALUES (?, ?, ?)",
                (approval.approval_id, approval.capability_id, approval.model_dump_json()),
            )

    def _approval_reason(
        self, connection: sqlite3.Connection, request: ConsumeRequest
    ) -> DecisionReason:
        """Validate an approval and its durable consumption count."""
        if not request.approval_required:
            return DecisionReason.ALLOW
        if request.approval_id is None:
            return DecisionReason.APPROVAL_REQUIRED
        row = connection.execute(
            "SELECT body, used FROM approvals WHERE id=?", (request.approval_id,)
        ).fetchone()
        if row is None:
            return DecisionReason.APPROVAL_INVALID
        try:
            approval = ApprovalGrant.model_validate_json(row[0])
        except ValueError as exc:
            raise StateUnavailableError("approval record is corrupt") from exc
        if (
            approval.approval_id != request.approval_id
            or approval.capability_id != request.capability_id
            or approval.intent_fingerprint != request.intent_fingerprint
            or approval.expires_at <= request.now
            or not 0 <= row[1] < approval.max_uses
        ):
            return DecisionReason.APPROVAL_INVALID
        return DecisionReason.ALLOW

    def consume(self, request: ConsumeRequest) -> ConsumeResult:
        """Commit replay marker, capability budget and approval budget together."""
        with self._transaction() as connection:
            request = replace(request, now=max(request.now, int(self._clock())))
            remaining = self._budget(connection, request.capability_id, request.max_uses)
            reason = self._consume_reason(connection, request, remaining)
            if reason is not DecisionReason.ALLOW:
                return ConsumeResult(False, reason, remaining)
            connection.execute(
                "INSERT INTO requests VALUES (?, ?)", (request.request_id, request.capability_id)
            )
            connection.execute(
                "UPDATE capabilities SET used=used+1 WHERE id=?", (request.capability_id,)
            )
            if request.approval_required:
                connection.execute(
                    "UPDATE approvals SET used=used+1 WHERE id=?", (request.approval_id,)
                )
            return ConsumeResult(True, DecisionReason.ALLOW, remaining - 1)

    def _consume_reason(
        self, connection: sqlite3.Connection, request: ConsumeRequest, remaining: int
    ) -> DecisionReason:
        """Evaluate state constraints while holding the transaction's write lock."""
        if request.expires_at is not None and request.now >= request.expires_at:
            return DecisionReason.EXPIRED
        if self._revoked(connection, request.capability_id):
            return DecisionReason.REVOKED
        if connection.execute(
            "SELECT 1 FROM requests WHERE id=?", (request.request_id,)
        ).fetchone():
            return DecisionReason.REPLAY_DETECTED
        if remaining == 0:
            return DecisionReason.USE_BUDGET_EXHAUSTED
        reason = self._approval_reason(connection, request)
        if reason is not DecisionReason.ALLOW:
            return reason
        capacity_reached = (
            connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            >= self.max_request_ids
        )
        return DecisionReason.STATE_UNAVAILABLE if capacity_reached else DecisionReason.ALLOW


def main() -> None:
    """Initialize a new operator-selected ledger from the command line."""
    parser = argparse.ArgumentParser(description="Initialize a NEW private authorization ledger")
    parser.add_argument("path", type=Path)
    initialize_database(parser.parse_args().path)


if __name__ == "__main__":
    main()
