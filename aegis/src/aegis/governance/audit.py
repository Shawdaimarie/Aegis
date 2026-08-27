"""Append-only, hash-chained audit log."""

from collections.abc import Iterator
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.errors import IntegrityError
from aegis.core.hashing import content_id

GENESIS = "sha256:" + "0" * 64


class AuditRecord(BaseModel):
    """One immutable entry. ``prev`` links to the previous record's ``id``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int
    at: datetime
    actor: str
    action: str
    resource: str
    decision: str
    detail: dict[str, str] = Field(default_factory=dict)
    prev: str
    id: str = ""

    def with_id(self) -> "AuditRecord":
        """Return a copy whose ``id`` is the content hash of every other field."""
        body = self.model_dump(mode="json", exclude={"id"})
        return self.model_copy(update={"id": content_id(body)})


class AuditLog:
    """In-memory hash chain. Adapters persist it; nothing may mutate history."""

    def __init__(self) -> None:
        """Start an empty chain."""
        self._records: list[AuditRecord] = []

    def append(
        self,
        actor: str,
        action: str,
        resource: str,
        decision: str,
        detail: dict[str, str] | None = None,
    ) -> AuditRecord:
        """Append a record and return it."""
        prev = self._records[-1].id if self._records else GENESIS
        rec = AuditRecord(
            seq=len(self._records),
            at=datetime.now(UTC),
            actor=actor,
            action=action,
            resource=resource,
            decision=decision,
            detail=detail or {},
            prev=prev,
        ).with_id()
        self._records.append(rec)
        return rec

    def verify(self) -> None:
        """Raise IntegrityError if any record has been altered or reordered."""
        prev = GENESIS
        for i, rec in enumerate(self._records):
            if rec.seq != i or rec.prev != prev or rec.with_id().id != rec.id:
                raise IntegrityError(f"audit chain broken at seq={i}")
            prev = rec.id

    def __iter__(self) -> Iterator[AuditRecord]:
        """Iterate records oldest first."""
        return iter(tuple(self._records))

    def __len__(self) -> int:
        """Number of records."""
        return len(self._records)
