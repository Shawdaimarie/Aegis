"""Bearer-token authentication and per-request identity."""

import hmac
import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status

from aegis.adapters.secrets import get_secret


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated caller."""

    subject: str


def require_principal(
    request: Request, authorization: str | None = Header(default=None)
) -> Principal:
    """Validate ``Authorization: Bearer <token>`` in constant time.

    Raises:
        HTTPException: 401 on missing or invalid credentials.
    """
    expected = get_secret("AEGIS_API_TOKEN")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    supplied = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    return Principal(subject=request.headers.get("X-Aegis-Subject", "api-client"))


def new_request_id() -> str:
    """Return a fresh, unguessable request identifier."""
    return secrets.token_urlsafe(12)
