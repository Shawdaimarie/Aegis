"""Durable single-host work queue with immutable requests and transactional claims."""

import argparse
import os
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from aegis.core.errors import PlatformError, StateUnavailableError
from aegis.core.work import InspectionReport, WorkDecision, WorkItem, WorkRequest

MAX_WORK_ITEMS = 10_000


class WorkConflictError(PlatformError):
    """A request was changed, already decided, expired or already claimed."""


def initialize_database(path: Path) -> None:
    """Provision a new private queue; never overwrite or migrate an existing file."""
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError("queue requires an absolute path in an existing directory")
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    connection = sqlite3.connect(path)
    try:
        with connection:
            connection.execute("CREATE TABLE metadata (version INTEGER NOT NULL)")
            connection.execute("INSERT INTO metadata VALUES (1)")
            connection.execute(
                "CREATE TABLE jobs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, "
                "request_key TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(tenant, request_key))"
            )
            connection.execute(
                "CREATE TABLE events (sequence INTEGER PRIMARY KEY, job_id TEXT NOT NULL, "
                "tenant TEXT NOT NULL, actor TEXT NOT NULL, state TEXT NOT NULL, "
                "at INTEGER NOT NULL, body TEXT NOT NULL)"
            )
    finally:
        connection.close()


class WorkQueue:
    """Open existing storage only; every transition commits with its attribution."""

    def __init__(self, path: Path) -> None:
        """Select an operator-provisioned queue."""
        if not path.is_absolute():
            raise StateUnavailableError("invalid queue path")
        self.path = path

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize transitions and fail closed on unavailable or malformed storage."""
        connection = None
        try:
            if self.path.is_symlink():
                raise StateUnavailableError("queue symlinks are forbidden")
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2)
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT version FROM metadata").fetchall() != [(1,)]:
                    raise StateUnavailableError("queue schema unavailable")
                yield connection
        except (sqlite3.Error, OSError) as exc:
            raise StateUnavailableError("work queue unavailable") from exc
        finally:
            if connection:
                connection.close()

    @staticmethod
    def decode(body: str) -> WorkItem:
        """Reject malformed stored work instead of assuming permission."""
        try:
            return WorkItem.model_validate_json(body)
        except ValueError as exc:
            raise StateUnavailableError("work record unavailable") from exc

    def get(self, connection: sqlite3.Connection, tenant: str, job_id: str) -> WorkItem:
        """Resolve work within the authenticated tenant only."""
        row = connection.execute(
            "SELECT body FROM jobs WHERE id=? AND tenant=?", (job_id, tenant)
        ).fetchone()
        if row is None:
            raise LookupError("work item not found")
        item = self.decode(row[0])
        if item.tenant != tenant or item.id != job_id:
            raise StateUnavailableError("work identity mismatch")
        return item

    @staticmethod
    def save(connection: sqlite3.Connection, item: WorkItem, actor: str) -> None:
        """Write state and attribution within the same transaction."""
        connection.execute("UPDATE jobs SET body=? WHERE id=?", (item.model_dump_json(), item.id))
        connection.execute(
            "INSERT INTO events(job_id,tenant,actor,state,at,body) VALUES(?,?,?,?,?,?)",
            (item.id, item.tenant, actor, item.status, item.updated_at, item.model_dump_json()),
        )

    def submit(self, tenant: str, actor: str, request: WorkRequest) -> WorkItem:
        """Deduplicate identical retries without silently changing their request."""
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT id FROM jobs WHERE tenant=? AND request_key=?",
                (tenant, request.request_key),
            ).fetchone()
            if row:
                item = self.get(connection, tenant, row[0])
                if item.request != request or item.requested_by != actor:
                    raise WorkConflictError("request key already used for different work")
                return item
            if connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= MAX_WORK_ITEMS:
                raise StateUnavailableError("queue capacity reached")
            now = int(time.time())
            item = WorkItem(
                id="work_" + secrets.token_hex(16),
                tenant=tenant,
                requested_by=actor,
                request=request,
                created_at=now,
                updated_at=now,
            )
            connection.execute(
                "INSERT INTO jobs VALUES(?,?,?,?)",
                (item.id, tenant, request.request_key, item.model_dump_json()),
            )
            self.save(connection, item, actor)
            return item

    def list_items(self, tenant: str) -> list[WorkItem]:
        """Return at most 100 recent requests within one tenant."""
        with self.transaction() as connection:
            ids = connection.execute(
                "SELECT id FROM jobs WHERE tenant=? ORDER BY rowid DESC LIMIT 100", (tenant,)
            ).fetchall()
            return [self.get(connection, tenant, row[0]) for row in ids]

    def decide(self, tenant: str, actor: str, job_id: str, decision: WorkDecision) -> WorkItem:
        """Record one immutable reviewer decision; duplicate decisions conflict."""
        with self.transaction() as connection:
            item = self.get(connection, tenant, job_id)
            if (
                item.status != "pending"
                and not (item.status == "approved" and decision.decision == "rejected")
            ) or item.revision != decision.expected_revision:
                raise WorkConflictError("work changed; refresh before deciding")
            item.status = decision.decision
            item.reviewer = actor
            item.decision_reason = decision.reason
            item.updated_at = int(time.time())
            item.approval_expires_at = item.updated_at + 300 if item.status == "approved" else None
            item.revision += 1
            self.save(connection, item, actor)
            return item

    def claim(self, tenant: str, actor: str, job_id: str) -> WorkItem:
        """Claim approved work exactly once; never requeue an interrupted attempt."""
        with self.transaction() as connection:
            item = self.get(connection, tenant, job_id)
            now = int(time.time())
            if (
                item.status != "approved"
                or not item.approval_expires_at
                or item.approval_expires_at <= now
            ):
                raise WorkConflictError("work is not approved, is expired or was already started")
            item.status = "running"
            item.revision += 1
            item.updated_at = now
            self.save(connection, item, actor)
            return item

    def finish(
        self, tenant: str, actor: str, job_id: str, result: InspectionReport | None
    ) -> WorkItem:
        """Record a report or generic failure; never persist tokens or upstream errors."""
        with self.transaction() as connection:
            item = self.get(connection, tenant, job_id)
            if item.status != "running":
                raise WorkConflictError("work is not running")
            item.status = "succeeded" if result else "failed"
            item.result = result
            item.error = None if result else "GitHub inspection unavailable; no automatic retry."
            item.updated_at = int(time.time())
            item.revision += 1
            self.save(connection, item, actor)
            return item


def main() -> None:
    """Initialize an explicitly selected new queue."""
    parser = argparse.ArgumentParser(description="Initialize a NEW private work queue")
    parser.add_argument("path", type=Path)
    initialize_database(parser.parse_args().path)


if __name__ == "__main__":
    main()
