"""Bearer-token authentication and per-request identity."""

import hmac
import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status

from aegis.adapters.secrets import get_secret
from aegis.core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated caller."""

    subject: str
    tenant: str = ""


def require_principal(
    request: Request, authorization: str | None = Header(default=None)
) -> Principal:
    """Validate ``Authorization: Bearer <token>`` in constant time.

    Raises:
        HTTPException: 401 on missing or invalid credentials.
    """
    try:
        expected = get_secret("AEGIS_API_TOKEN")
    except ConfigurationError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "authentication unavailable"
        ) from exc
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    supplied = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    # One shared credential identifies one service principal, never a claimed human.
    return Principal(subject="api-client")


def new_request_id() -> str:
    """Return a fresh, unguessable request identifier."""
    return secrets.token_urlsafe(12)


def require_approver(authorization: str | None = Header(default=None)) -> Principal:
    """Authenticate the operator-configured approval identity with a separate credential.

    The deployment must keep this credential under the human reviewer's control.
    A source or API request cannot register its own reviewer identity.
    """
    try:
        expected = get_secret("AEGIS_APPROVER_TOKEN")
        subject = get_secret("AEGIS_APPROVER_SUBJECT")
        tenant = get_secret("AEGIS_APPROVER_TENANT")
        if hmac.compare_digest(expected.encode(), get_secret("AEGIS_API_TOKEN").encode()):
            raise ConfigurationError("approval credential must be distinct")
    except ConfigurationError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "human approval unavailable"
        ) from exc
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing approval credential")
    supplied = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid approval credential")
    return Principal(subject=subject, tenant=tenant)
