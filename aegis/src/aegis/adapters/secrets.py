"""The only sanctioned path for reading secrets."""

import os

from aegis.core.errors import ConfigurationError


def get_secret(name: str) -> str:
    """Read ``name`` from the environment.

    Raises:
        ConfigurationError: Secret is absent or empty.
    """
    value = os.environ.get(name, "")
    if not value:
        raise ConfigurationError(f"required secret '{name}' is not set")
    return value
