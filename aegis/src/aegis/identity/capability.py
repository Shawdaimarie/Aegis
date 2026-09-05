"""Signed capability encoding and monotonic delegation rules."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from aegis.core.errors import IntegrityError
from aegis.core.hashing import canonical_json
from aegis.identity.models import CapabilityGrant

TOKEN_PREFIX = "aegis1"
MIN_SIGNING_KEY_BYTES = 32


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityError("capability token contains invalid base64url data") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"capability payload contains duplicate key: {key}")
        result[key] = value
    return result


def resource_covers(parent: str, child: str) -> bool:
    """Return whether one exact or terminal-prefix resource contains another."""
    if parent == child:
        return True
    if not parent.endswith("/**"):
        return False
    prefix = parent[:-3]
    return child == prefix or child.startswith(prefix + "/")


def request_resource_allowed(patterns: tuple[str, ...], resource: str) -> bool:
    """Return whether a requested resource is covered by any declared pattern."""
    return any(resource_covers(pattern, resource) for pattern in patterns)


def validate_monotonic_delegation(parent: CapabilityGrant, child: CapabilityGrant) -> None:
    """Reject a child capability that broadens any parent authority dimension."""
    failures: list[str] = []
    if child.parent_capability_id != parent.capability_id:
        failures.append("parent capability id")
    if child.issuer != parent.subject:
        failures.append("delegating principal")
    if child.tenant != parent.tenant:
        failures.append("tenant")
    if child.audience != parent.audience:
        failures.append("audience")
    if not set(child.actions).issubset(parent.actions):
        failures.append("actions")
    broadens_resource = any(
        not request_resource_allowed(parent.resources, resource)
        for resource in child.resources
    )
    if broadens_resource:
        failures.append("resources")
    if child.not_before < parent.not_before:
        failures.append("not-before time")
    if child.expires_at > parent.expires_at:
        failures.append("expiration time")
    if child.max_uses > parent.max_uses:
        failures.append("use budget")
    if parent.requires_approval and not child.requires_approval:
        failures.append("approval requirement")
    for key, expected in parent.context_constraints.items():
        if child.context_constraints.get(key) != expected:
            failures.append(f"context constraint {key}")
    if child.delegation_depth != parent.delegation_depth + 1:
        failures.append("delegation depth")
    if failures:
        raise ValueError("delegation broadens parent authority: " + ", ".join(failures))


class CapabilityCodec:
    """Issue and verify compact HMAC-SHA256 capability envelopes.

    This reference codec is intentionally dependency-free. Production systems
    should use a managed key service and asymmetric workload identity so a
    verifier does not also hold the authority to mint capabilities.
    """

    def __init__(self, signing_key: bytes | str, *, key_id: str = "local-hmac-v1") -> None:
        """Bind one signing key and explicit key identifier."""
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        if len(key) < MIN_SIGNING_KEY_BYTES:
            message = f"capability signing key must be at least {MIN_SIGNING_KEY_BYTES} bytes"
            raise ValueError(message)
        if not key_id or "." in key_id:
            raise ValueError("key_id must be non-empty and cannot contain dots")
        self._key = key
        self.key_id = key_id

    def encode(self, grant: CapabilityGrant) -> str:
        """Return a signed compact capability token."""
        if grant.key_id != self.key_id:
            raise ValueError("grant key_id does not match codec key_id")
        payload = canonical_json(grant.model_dump(mode="json")).encode("utf-8")
        encoded = _b64url_encode(payload)
        signed = f"{TOKEN_PREFIX}.{self.key_id}.{encoded}".encode("ascii")
        signature = _b64url_encode(hmac.new(self._key, signed, hashlib.sha256).digest())
        return signed.decode("ascii") + "." + signature

    def decode(self, token: str) -> CapabilityGrant:
        """Validate the signature and return a strict capability grant."""
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != TOKEN_PREFIX:
            raise IntegrityError("capability token has an unsupported format")
        prefix, key_id, encoded, signature = parts
        if key_id != self.key_id:
            raise IntegrityError("capability token uses an unknown key id")
        signed = f"{prefix}.{key_id}.{encoded}".encode("ascii")
        expected = hmac.new(self._key, signed, hashlib.sha256).digest()
        supplied = _b64url_decode(signature)
        if not hmac.compare_digest(supplied, expected):
            raise IntegrityError("capability signature is invalid")
        try:
            payload = json.loads(
                _b64url_decode(encoded).decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
            if not isinstance(payload, Mapping):
                raise IntegrityError("capability payload must be a JSON object")
            grant = CapabilityGrant.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise IntegrityError("capability payload is invalid") from exc
        if grant.key_id != key_id:
            raise IntegrityError("capability payload key id does not match token header")
        return grant
