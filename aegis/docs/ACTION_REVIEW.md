# Action Review: first Identity & Access milestone

The console now has a separate reviewer connection and a manual action-review workspace.
A deployment-configured reviewer credential maps to a named subject and tenant. This is
not passkey authentication, identity-provider integration or a persistent approval inbox.

GET /v1/reviews/me returns the authenticated subject and tenant. POST /v1/reviews/preview
validates a proposal without granting approval or consuming a use. POST /v1/reviews/approve
revalidates scope and revocation, derives human identity from authentication, and persists
one exact-intent approval. Proposals cannot supply an approver, request multiple uses or
request a validity period longer than 300 seconds. Capability expiry can shorten validity.
The preview expiry is calculated at preview time; actual expiry is calculated at approval.

Proposal format:

```json
{
  "capability_token": "SIGNED_CAPABILITY_FROM_THE_CONTROL_PLANE",
  "intent": {
    "actor": {"id": "agent:planner", "kind": "agent", "tenant": "acme"},
    "tenant": "acme",
    "audience": "service:documents",
    "action": "document.read",
    "resource": "document://acme/report",
    "context": {"purpose": "Human-requested review"}
  },
  "ttl_seconds": 300,
  "max_uses": 1
}
```

All action parameters must be represented in the reviewed intent/context and enforced
by the executor. Costs and consequences are not independently inferred or validated.
The UI treats source text as text, never HTML or instructions. Editing invalidates the
preview. Approval submits the reviewed snapshot, disables repeated clicks and never
retries automatically after an uncertain response. A reconnect cannot restore a late
response from an earlier connection. Credentials and drafts remain in page memory.
Disconnecting does not cancel an approval already submitted to the server.

Discard draft clears only the local proposal. It is not a durable denial or revocation.
Approval does not execute an action or bypass automation controls. Existing administrative
approval endpoints retain their prior policy; the new one-use/300-second limits apply to
this review workspace, not all administrative approval mechanisms.

Production follow-up: select an identity provider and approved application origin; use
its supported passkey/MFA flow and verified subject/tenant mappings. Design session
revocation, secure recovery and fresh authentication for sensitive approval. A persistent
inbox additionally needs immutable proposal IDs, expiration, durable denial history and
idempotent decisions. Executor enforcement and independently retained audit evidence remain
separate work. Do not treat the present credential mapping as proof of physical human presence.

Validation covers authenticated identity, tenant isolation, non-consuming preview,
identity injection, limits, revocation between preview and approval, exact single-use
consumption, UI edits, late responses and uncertain submissions. Browser rendering remains
unverified while browser policy verification is unavailable.
