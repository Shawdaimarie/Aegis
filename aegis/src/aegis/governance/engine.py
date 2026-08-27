"""The policy engine evaluates boundaries at lifecycle checkpoints and records outcomes."""

from collections.abc import Sequence
from dataclasses import dataclass

from aegis.core.errors import GovernanceViolationError
from aegis.core.types import Checkpoint, RunContext, Severity
from aegis.governance.audit import AuditLog
from aegis.governance.boundary import Boundary


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of one evaluation pass."""

    checkpoint: Checkpoint
    advisories: tuple[str, ...]
    blocked_by: str | None
    halted_by: str | None

    @property
    def allowed(self) -> bool:
        """True when the run may proceed."""
        return self.blocked_by is None and self.halted_by is None


class PolicyEngine:
    """Evaluates a fixed, read-only set of boundaries.

    Boundaries are supplied once at construction; there is no method to add, remove,
    or downgrade them afterwards. This is what makes HALT boundaries undisableable.
    """

    def __init__(self, boundaries: Sequence[Boundary], audit: AuditLog) -> None:
        """Bind an immutable boundary set and an audit sink."""
        ids = [b.id for b in boundaries]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            msg = f"duplicate boundary ids: {dupes}"
            raise ValueError(msg)
        self._boundaries: tuple[Boundary, ...] = tuple(boundaries)
        self._audit = audit

    @property
    def boundaries(self) -> tuple[Boundary, ...]:
        """The immutable boundary set."""
        return self._boundaries

    def evaluate(
        self, checkpoint: Checkpoint, ctx: RunContext, *, raise_on_block: bool = True
    ) -> Decision:
        """Evaluate every boundary registered for ``checkpoint``.

        Args:
            checkpoint: Lifecycle point being evaluated.
            ctx: Immutable run snapshot.
            raise_on_block: If True, raise GovernanceViolationError for BLOCKING/HALT crossings
                after recording them. If False, return the Decision silently.

        Returns:
            The Decision for this pass.

        Raises:
            GovernanceViolationError: A BLOCKING or HALT boundary was crossed.
        """
        advisories: list[str] = []
        blocked: str | None = None
        halted: str | None = None

        for b in self._boundaries:
            if checkpoint not in b.checkpoints:
                continue
            crossed = b.crossed(ctx)
            self._audit.append(
                actor="policy-engine",
                action=f"evaluate:{checkpoint}",
                resource=f"boundary:{b.id}",
                decision="crossed" if crossed else "clear",
                detail={"run_id": ctx.run_id, "step": str(ctx.step), "severity": b.severity},
            )
            if not crossed:
                continue
            if b.severity is Severity.ADVISORY:
                advisories.append(b.id)
            elif b.severity is Severity.BLOCKING:
                blocked = blocked or b.id
            else:
                halted = halted or b.id

        decision = Decision(checkpoint, tuple(advisories), blocked, halted)
        self._audit.append(
            actor="policy-engine",
            action=f"decide:{checkpoint}",
            resource=f"run:{ctx.run_id}",
            decision="allow" if decision.allowed else "deny",
            detail={"blocked_by": blocked or "", "halted_by": halted or ""},
        )
        if raise_on_block and not decision.allowed:
            fired = halted or blocked or ""
            b = next(x for x in self._boundaries if x.id == fired)
            raise GovernanceViolationError(b.id, b.severity, b.rationale)
        return decision
