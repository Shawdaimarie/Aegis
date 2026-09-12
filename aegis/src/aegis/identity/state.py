"""Thread-safe reference state for revocation, replay, usage, and approvals."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from aegis.identity.models import ApprovalGrant, DecisionReason


@dataclass(frozen=True, slots=True)
class ConsumeRequest:
    """Stateful inputs required for one authorization consumption."""

    capability_id: str
    max_uses: int
    request_id: str
    now: int
    approval_required: bool
    approval_id: str | None
    intent_fingerprint: str


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Atomic result of consuming a capability and optional approval."""

    allowed: bool
    reason: DecisionReason
    remaining_uses: int


class AuthorizationState:
    """Bounded in-memory authorization state.

    This is suitable for tests and a single-process reference deployment. A
    production control plane needs durable, strongly consistent state with
    explicit retention and failure behavior.
    """

    def __init__(self, *, max_request_ids: int = 100_000) -> None:
        """Initialize bounded single-process authorization state."""
        if max_request_ids < 1:
            raise ValueError("max_request_ids must be positive")
        self._lock = Lock()
        self._uses: dict[str, int] = {}
        self._revocations: dict[str, str] = {}
        self._approvals: dict[str, ApprovalGrant] = {}
        self._approval_uses: dict[str, int] = {}
        self._children: dict[str, set[str]] = {}
        self._request_ids: set[str] = set()
        self._max_request_ids = max_request_ids

    def revoke(self, capability_id: str, reason: str) -> None:
        """Revoke a capability and every registered descendant idempotently."""
        with self._lock:
            pending = [capability_id]
            while pending:
                current = pending.pop()
                if current in self._revocations:
                    continue
                self._revocations[current] = reason
                pending.extend(self._children.get(current, set()))

    def register_delegation(
        self,
        *,
        parent_capability_id: str,
        child_capability_id: str,
        reserved_uses: int,
        parent_max_uses: int,
    ) -> int:
        """Reserve parent authority and register the child for revocation cascade."""
        with self._lock:
            if parent_capability_id in self._revocations:
                raise ValueError("revoked capability cannot be delegated")
            used = self._uses.get(parent_capability_id, 0)
            remaining = max(0, parent_max_uses - used)
            if reserved_uses > remaining:
                raise ValueError("delegated use budget exceeds the parent remaining budget")
            self._uses[parent_capability_id] = used + reserved_uses
            self._children.setdefault(parent_capability_id, set()).add(child_capability_id)
            return remaining - reserved_uses

    def is_revoked(self, capability_id: str) -> bool:
        """Return whether the capability is revoked."""
        with self._lock:
            return capability_id in self._revocations

    def remaining_uses(self, capability_id: str, max_uses: int) -> int:
        """Return the non-negative remaining use budget."""
        with self._lock:
            return max(0, max_uses - self._uses.get(capability_id, 0))

    def store_approval(self, approval: ApprovalGrant) -> None:
        """Store one immutable approval grant."""
        with self._lock:
            if approval.approval_id in self._approvals:
                raise ValueError(f"duplicate approval id: {approval.approval_id}")
            self._approvals[approval.approval_id] = approval

    def consume(self, request: ConsumeRequest) -> ConsumeResult:
        """Atomically enforce replay, revocation, use budget, and approval budget."""
        with self._lock:
            used = self._uses.get(request.capability_id, 0)
            remaining = max(0, request.max_uses - used)
            if request.capability_id in self._revocations:
                return ConsumeResult(False, DecisionReason.REVOKED, remaining)
            if request.request_id in self._request_ids:
                return ConsumeResult(False, DecisionReason.REPLAY_DETECTED, remaining)
            if remaining == 0:
                return ConsumeResult(False, DecisionReason.USE_BUDGET_EXHAUSTED, 0)

            reason, approval = self._approval_for(request)
            if reason is not DecisionReason.ALLOW:
                return ConsumeResult(False, reason, remaining)

            if len(self._request_ids) >= self._max_request_ids:
                return ConsumeResult(False, DecisionReason.STATE_UNAVAILABLE, remaining)
            self._request_ids.add(request.request_id)
            self._uses[request.capability_id] = used + 1
            if approval is not None and request.approval_id is not None:
                approval_uses = self._approval_uses.get(request.approval_id, 0)
                self._approval_uses[request.approval_id] = approval_uses + 1
            return ConsumeResult(True, DecisionReason.ALLOW, remaining - 1)

    def _approval_for(self, request: ConsumeRequest) -> tuple[DecisionReason, ApprovalGrant | None]:
        """Validate approval while the caller holds the state lock."""
        if not request.approval_required:
            return DecisionReason.ALLOW, None
        if request.approval_id is None:
            return DecisionReason.APPROVAL_REQUIRED, None
        approval = self._approvals.get(request.approval_id)
        approval_uses = self._approval_uses.get(request.approval_id, 0)
        if (
            approval is None
            or approval.capability_id != request.capability_id
            or approval.intent_fingerprint != request.intent_fingerprint
            or approval.expires_at <= request.now
            or approval_uses >= approval.max_uses
        ):
            return DecisionReason.APPROVAL_INVALID, None
        return DecisionReason.ALLOW, approval
