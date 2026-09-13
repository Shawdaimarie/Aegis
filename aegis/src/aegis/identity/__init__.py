"""Agent identity, delegated capabilities, approvals, and authorization."""

from aegis.identity.capability import CapabilityCodec, resource_covers
from aegis.identity.control_plane import IdentityControlPlane, intent_fingerprint
from aegis.identity.models import (
    ApprovalGrant,
    ApprovalRequest,
    AuthorizationDecision,
    AuthorizationIntent,
    AuthorizationRequest,
    CapabilityGrant,
    DecisionReason,
    DelegateCapabilityRequest,
    InspectCapabilityRequest,
    IssueCapabilityRequest,
    IssuedCapability,
    Principal,
    PrincipalKind,
    RevokeCapabilityRequest,
)
from aegis.identity.state import AuthorizationState

__all__ = [
    "ApprovalGrant",
    "ApprovalRequest",
    "AuthorizationDecision",
    "AuthorizationIntent",
    "AuthorizationRequest",
    "AuthorizationState",
    "CapabilityCodec",
    "CapabilityGrant",
    "DecisionReason",
    "DelegateCapabilityRequest",
    "IdentityControlPlane",
    "InspectCapabilityRequest",
    "IssueCapabilityRequest",
    "IssuedCapability",
    "Principal",
    "PrincipalKind",
    "RevokeCapabilityRequest",
    "intent_fingerprint",
    "resource_covers",
]
