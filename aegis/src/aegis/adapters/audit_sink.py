"""Persist the audit chain as newline-delimited JSON. Append-only."""

from pathlib import Path

from aegis.governance.audit import AuditLog


def export_jsonl(log: AuditLog, path: Path) -> int:
    """Append every record not yet on disk. Returns the number written."""
    existing = 0
    if path.exists():
        with path.open("rb") as fh:
            existing = sum(1 for _ in fh)
    written = 0
    with path.open("a", encoding="utf-8") as fh:
        for rec in log:
            if rec.seq < existing:
                continue
            fh.write(rec.model_dump_json() + "\n")
            written += 1
    return written
