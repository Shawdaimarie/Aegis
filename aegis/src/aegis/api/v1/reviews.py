"""Named human review of exact action proposals without caller-selected identity."""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from aegis.api.v1.security import Principal, require_approver
from aegis.core.errors import IntegrityError
from aegis.identity import ApprovalRequest, IdentityControlPlane
from aegis.identity.models import AuthorizationIntent

Reviewer = Annotated[Principal, Depends(require_approver)]


class ReviewProposal(BaseModel):
    """Action data only; authenticated identity is owned by the server."""

    model_config = ConfigDict(extra="forbid")
    capability_token: str = Field(min_length=32, repr=False)
    intent: AuthorizationIntent
    ttl_seconds: int = Field(ge=15, le=300, default=300)
    max_uses: int = Field(ge=1, le=1, default=1)

    def approval_request(self, reviewer: Principal) -> ApprovalRequest:
        """Bind the proposal to the authenticated reviewer and enforce tenant isolation."""
        if self.intent.tenant != reviewer.tenant:
            raise HTTPException(403, "reviewer tenant mismatch")
        return ApprovalRequest.model_validate(
            {
                **self.model_dump(),
                "approver": {"id": reviewer.subject, "tenant": reviewer.tenant, "kind": "human"},
            }
        )


def install_review_routes(app: FastAPI, identity: IdentityControlPlane) -> None:
    """Install a read-only preview and an explicit single-use approval action."""

    @app.get("/v1/reviews/me")
    async def reviewer_profile(reviewer: Reviewer) -> dict[str, str]:
        """Show server-authenticated identity without exposing credentials."""
        return {
            "subject": reviewer.subject,
            "tenant": reviewer.tenant,
            "authentication": "configured reviewer credential",
        }

    @app.post("/v1/reviews/preview")
    async def preview(body: ReviewProposal, reviewer: Reviewer) -> dict[str, object]:
        """Preview validated scope without issuing an approval or consuming budgets."""
        request = body.approval_request(reviewer)
        try:
            return identity.review_approval(request)
        except (IntegrityError, ValueError) as exc:
            raise HTTPException(
                422, "proposal is invalid or outside current capability scope"
            ) from exc

    @app.post("/v1/reviews/approve", status_code=201)
    async def approve(body: ReviewProposal, reviewer: Reviewer) -> dict[str, object]:
        """Revalidate and persist an approval attributed to the authenticated human."""
        request = body.approval_request(reviewer)
        try:
            return identity.approve(request).model_dump(mode="json")
        except (IntegrityError, ValueError) as exc:
            raise HTTPException(
                422, "proposal is invalid or outside current capability scope"
            ) from exc
