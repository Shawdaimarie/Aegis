# ADR-0003: Short-lived capabilities for agent authorization

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

A shared service credential proves only that a request reached Aegis through an
administrative boundary. It does not express which AI agent is acting, on whose
behalf, for which tenant and audience, against which action and resource, under
which human approval, or with what lifetime and use budget.

The first identity milestone also needs to remain runnable in CI without an
external identity provider or key-management service.

## Decision

Aegis will use a versioned, signed capability envelope for the reference
implementation.

The envelope uses canonical JSON and HMAC-SHA256 from the Python standard
library. This is an application of established primitives, not a custom
cryptographic algorithm. The token includes an explicit key identifier and is
validated with constant-time comparison.

Capabilities are:

- tenant- and audience-bound;
- subject-specific;
- scoped to explicit actions and resources;
- time-limited;
- use-limited;
- optionally approval- and context-bound; and
- delegable only through monotonic narrowing.

Stateful replay, approval, revocation, descendant, and use-budget controls are
implemented behind a dedicated state boundary.

## Consequences

### Positive

- The complete protocol can be inspected and tested without external services.
- Authority becomes explicit, portable, and independent of model output.
- Delegation and approval have enforceable invariants.
- The system emits stable reason codes and audit evidence.
- Future OIDC, SPIFFE, cloud workload identity, or asymmetric token adapters can
  map into the same domain contracts.

### Negative

- A symmetric verifier can also mint capabilities if it holds the key.
- In-memory state does not survive restart and cannot coordinate replicas.
- The shared administrative bearer token remains a bootstrap mechanism.
- Resource matching is intentionally limited and not a general policy language.

## Production migration

A production implementation should:

1. separate issuer and verifier roles;
2. use asymmetric signatures or a remote managed signer;
3. store keys in KMS or HSM-backed infrastructure;
4. bind principals to federated human or workload identity;
5. persist replay, approval, revocation, delegation, and use state in a strongly
   consistent store;
6. anchor audit evidence externally; and
7. enforce decisions at protected tool boundaries outside agent control.

## Rejected alternatives

### Ambient service identity only

Rejected because it cannot express delegated, operation-specific authority for
one agent acting on behalf of another principal.

### General-purpose policy language in the first milestone

Rejected because it increases parser, evaluation, and policy-conflict risk
before the core identity and delegation invariants are established.

### Self-signed custom public-key format

Rejected because introducing key parsing, algorithm selection, and rotation
without a vetted library or external identity system would add unnecessary
cryptographic risk.

## Verification

Unit and API tests cover tampering, wrong keys, temporal validity, tenant,
audience, principal, action, resource, context, approval, replay, use budgets,
delegation narrowing, parent-budget reservation, and revocation cascade.
