# Agent Identity and Delegated Authorization Control Plane

## Problem statement

A language model can generate a syntactically valid tool call without possessing
legitimate authority to execute it. Authentication of the surrounding service is
not enough: a protected system also needs to know which human, service, or agent
is acting; on whose behalf; for which tenant and audience; against which action
and resource; under which contextual and approval constraints; and for how long.

Aegis implements a compact reference control plane for making those properties
explicit and testable.

## Design goals

1. **Default deny.** Authority must be presented and validated for every request.
2. **Least privilege.** Capabilities carry only declared actions and resources.
3. **Short lifetime.** Every capability has not-before and expiration times.
4. **No privilege amplification.** Delegation can narrow but never broaden.
5. **Human control where required.** Approval binds to one exact operation.
6. **Replay resistance.** A request identifier and bounded use ledger prevent
   successful reuse inside the reference process.
7. **Auditable decisions.** Every security-relevant transition is recorded.
8. **Explicit limitations.** Development components are not presented as
   production-grade federated identity infrastructure.

## Principal model

A principal is one of:

- `human` — a person authorized through an external administrative boundary;
- `agent` — an AI-driven workload acting under delegated authority; or
- `service` — a non-agent workload or control-plane component.

Each principal has a stable identifier and exactly one tenant. The reference
model does not infer tenant membership from a name or token string.

## Capability envelope

The signed grant contains:

| Field | Security purpose |
|---|---|
| `capability_id` | Stable revocation, audit, and delegation reference |
| `key_id` | Explicit signing-key version |
| `issuer` | Principal that created the grant |
| `subject` | Only principal allowed to use it |
| `tenant` | Organizational isolation boundary |
| `audience` | Intended protected service |
| `actions` | Closed operation set |
| `resources` | Exact or terminal-prefix resource set |
| `issued_at`, `not_before`, `expires_at` | Temporal validity |
| `max_uses` | Bounded successful-use budget |
| `requires_approval` | Human-control requirement |
| `context_constraints` | Required environment, region, workflow, or other exact values |
| `parent_capability_id` | Delegation lineage |
| `delegation_depth` | Bounded chain depth |

The compact token format is:

```text
aegis1.<key-id>.<base64url-canonical-json>.<base64url-hmac-sha256>
```

The signature covers the version marker, key identifier, and payload. Verification
uses constant-time comparison. JSON parsing rejects duplicate keys and unknown
model fields.

## Resource semantics

Resource authorization is deliberately small and reviewable:

- an exact resource matches only itself;
- a resource ending in `/**` matches that prefix and descendants; and
- no other wildcard syntax is accepted.

For example:

```text
ledger://acme/invoices/**
```

covers:

```text
ledger://acme/invoices
ledger://acme/invoices/2026
ledger://acme/invoices/2026/09
```

but does not cover `ledger://other/invoices/1` or `ledger://acme/payroll/1`.

## Authorization sequence

```text
verify token signature and schema
        │
        ▼
check time, tenant, subject, audience, action, resource, and context
        │
        ▼
atomically check revocation, request replay, use budget, and approval
        │
        ▼
consume use/approval only when allowed
        │
        ▼
return stable decision reason and append audit record
```

A denied request does not consume the capability budget. A successful request
adds its request identifier to the replay ledger and consumes one use.

## Human approval

An approval is not a generic boolean. Aegis hashes the complete authorization
intent:

- actor;
- tenant;
- audience;
- action;
- resource; and
- sorted context.

The approval is stored with an expiration and use budget. Changing any bound
field makes the approval invalid for the new request.

## Delegation

A child grant must satisfy all of these invariants:

- issuer equals the parent subject;
- tenant and audience are unchanged;
- actions are a subset;
- every child resource is contained by a parent resource;
- the child validity interval is inside the parent interval;
- child use budget does not exceed remaining parent budget;
- parent approval requirements remain in force;
- every parent context constraint remains unchanged;
- delegation depth increases by exactly one; and
- the parent use budget reserves the authority assigned to the child.

Parent revocation cascades to every child registered in the reference state.

## Stable decision reasons

A caller receives an explicit reason rather than a generic failure:

- `allow`
- `invalid_token`
- `not_yet_valid`
- `expired`
- `revoked`
- `principal_mismatch`
- `tenant_mismatch`
- `audience_mismatch`
- `action_denied`
- `resource_denied`
- `context_mismatch`
- `approval_required`
- `approval_invalid`
- `use_budget_exhausted`
- `replay_detected`
- `state_unavailable`

Reason codes support operational diagnostics and evaluation. They must not be
expanded into responses that reveal secret material or internal policy details.

## API workflow

The administrative API remains protected by the existing bearer-token control.
A typical reference flow is:

1. `POST /v1/identity/capabilities`
2. optionally `POST /v1/identity/capabilities/delegate`
3. optionally `POST /v1/identity/approvals`
4. `POST /v1/authorization/check`
5. when required, `POST /v1/identity/revocations`
6. `GET /v1/audit` to verify and inspect the audit tail

The bearer token is an administrative bootstrap mechanism. Production systems
should replace it with federated human and workload identity, role separation,
and explicit issuer policy.

## Operational requirements for production

A production implementation should add:

- asymmetric signatures and verifier-only public keys;
- managed key rotation through KMS or HSM-backed issuers;
- workload identity such as SPIFFE-compatible identities or equivalent cloud
  workload credentials;
- reviewed operation of the durable single-host ledger and a transactional migration
  plan before multi-host deployment;
- issuer and policy-administrator separation of duties;
- external audit anchoring and retention controls;
- privacy classification and redaction rules;
- clock-skew policy and trusted time sources;
- policy rollout, simulation, and rollback procedures;
- incident-response and break-glass governance; and
- independent penetration and architecture review.

## Verification

The repository tests cover signature tampering, wrong signing keys, temporal
validity, subject/tenant/audience/action/resource/context mismatches, replay,
use exhaustion, exact-intent approval, privilege-escalating delegation, parent
budget reservation, revocation cascade, API authentication, and audit integrity.

The CI gate additionally enforces formatting, linting, architectural import
contracts, strict typing, documentation coverage, branch coverage, static
security analysis, dependency audit, package build, container build, and CodeQL.

## Scope boundary

Aegis demonstrates an enforceable design and test strategy. It does not claim
that HMAC tokens, local memory, a shared administrative token, or one repository
constitute a complete enterprise identity platform. The implementation is
intended to make assumptions, invariants, failure modes, and migration paths
inspectable.
