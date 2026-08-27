"""Boundary definitions: a predicate over RunContext plus metadata and severity."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.core.types import Checkpoint, RunContext, Severity


class Comparator(StrEnum):
    """Supported predicate operators. Kept closed so boundaries are auditable."""

    GT = ">"
    GE = ">="
    LT = "<"
    LE = "<="
    EQ = "=="
    NE = "!="
    MISSING = "missing"
    PRESENT = "present"


class Predicate(BaseModel):
    """A single comparison against a dotted path in RunContext."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    op: Comparator
    value: float | str | None = None

    @model_validator(mode="after")
    def _numeric_ops_need_numbers(self) -> "Predicate":
        """Ordered comparators require a value and always compare as float."""
        ordered = {Comparator.GT, Comparator.GE, Comparator.LT, Comparator.LE}
        if self.op in ordered:
            if self.value is None:
                raise ValueError(f"operator {self.op} requires a numeric value")
            object.__setattr__(self, "value", float(self.value))
        return self

    def holds(self, ctx: RunContext) -> bool:
        """Return True when the predicate is satisfied (i.e. the boundary is crossed)."""
        actual: Any = ctx.get(self.path)
        if self.op is Comparator.MISSING:
            return actual is None
        if self.op is Comparator.PRESENT:
            return actual is not None
        if actual is None:
            return False
        if isinstance(self.value, float) and not isinstance(actual, (int, float)):
            return False
        ops = {
            Comparator.GT: lambda a, v: a > v,
            Comparator.GE: lambda a, v: a >= v,
            Comparator.LT: lambda a, v: a < v,
            Comparator.LE: lambda a, v: a <= v,
            Comparator.EQ: lambda a, v: a == v,
            Comparator.NE: lambda a, v: a != v,
        }
        return bool(ops[self.op](actual, self.value))


class Boundary(BaseModel):
    """A named operational constraint with severity, ownership, and rationale."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    title: str
    severity: Severity
    checkpoints: frozenset[Checkpoint]
    predicate: Predicate
    owner: str
    rationale: str

    def crossed(self, ctx: RunContext) -> bool:
        """Return True if this boundary is crossed in ``ctx``."""
        return self.predicate.holds(ctx)
