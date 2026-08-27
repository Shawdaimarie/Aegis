"""Load boundaries from schema-validated YAML. This is the only entry point for boundaries."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aegis.core.errors import ConfigurationError
from aegis.governance.boundary import Boundary


class BoundaryFile(BaseModel):
    """Top-level schema of a governance YAML file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(ge=1)
    boundaries: tuple[Boundary, ...]


def load_boundaries(path: Path) -> tuple[Boundary, ...]:
    """Parse and validate ``path``; unknown keys are errors.

    Raises:
        ConfigurationError: File missing or fails schema validation.
    """
    try:
        raw = yaml.safe_load(path.read_text())
        return BoundaryFile.model_validate(raw).boundaries
    except FileNotFoundError as exc:
        raise ConfigurationError(f"governance file not found: {path}") from exc
    except (yaml.YAMLError, ValueError) as exc:
        raise ConfigurationError(f"invalid governance file {path}: {exc}") from exc
