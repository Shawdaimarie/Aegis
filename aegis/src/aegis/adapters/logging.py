"""Structured logging with mandatory secret redaction."""

import re
from collections.abc import MutableMapping
from typing import Any

import structlog

_SECRET_KEYS = re.compile(r"(token|secret|password|api[_-]?key|authorization)", re.IGNORECASE)


def redact(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:  # noqa: ANN401 - structlog processor signature
    """Replace values of secret-looking keys with a fixed marker."""
    for k in list(event):
        if _SECRET_KEYS.search(k):
            event[k] = "[REDACTED]"
    return event


def configure() -> None:
    """Install the platform logging chain. Idempotent."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact,
            structlog.processors.JSONRenderer(),
        ]
    )


def get_logger(name: str) -> Any:  # noqa: ANN401 - structlog returns a bound logger proxy
    """Return a bound logger."""
    return structlog.get_logger(name)
