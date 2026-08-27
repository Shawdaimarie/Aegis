"""Shared value types."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """How the policy engine reacts when a boundary predicate is true."""

    ADVISORY = "ADVISORY"
    BLOCKING = "BLOCKING"
    HALT = "HALT"


class Checkpoint(StrEnum):
    """Points in a run lifecycle at which governance is evaluated."""

    PRE_RUN = "pre_run"
    STEP = "step"
    POST_RUN = "post_run"


class ScenarioKind(StrEnum):
    """Training scenario. There is deliberately no default."""

    INDEPENDENT = "independent"
    DEPENDENT = "dependent"


class RunContext(BaseModel):
    """Immutable snapshot of a run against which boundaries are evaluated."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    scenario: ScenarioKind
    step: int = Field(ge=0, default=0)
    metrics: dict[str, float] = Field(default_factory=dict)
    resources: dict[str, float] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)

    def get(self, path: str) -> Any:  # noqa: ANN401 - dynamic lookup over a small closed set
        """Resolve a dotted path such as ``metrics.loss`` or ``resources.gpu_hours``."""
        head, _, tail = path.partition(".")
        bucket = getattr(self, head, None)
        if isinstance(bucket, dict):
            return bucket.get(tail)
        return bucket if not tail else None
