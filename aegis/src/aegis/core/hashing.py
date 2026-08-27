"""Content addressing and canonical hashing."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def canonical_json(obj: Mapping[str, Any] | list[Any]) -> str:
    """Serialise ``obj`` deterministically (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: bytes | str) -> str:
    """Return the hex SHA-256 of ``data``."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def content_id(obj: Mapping[str, Any] | list[Any]) -> str:
    """Return a content identifier of the form ``sha256:<hex>`` for a JSON-able object."""
    return f"sha256:{sha256_hex(canonical_json(obj))}"
