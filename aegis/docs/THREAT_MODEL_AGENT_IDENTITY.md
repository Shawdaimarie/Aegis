# Threat Model: Agent Identity and Delegated Authorization

## Scope

This document analyzes the Aegis reference identity control plane. It covers
capability issuance, token verification, delegation, human approval, replay and
use budgets, revocation, authorization decisions, and audit records.

It does not model every risk in the underlying language model, operating system,
network, cloud account, or protected business application.

## Protected assets

- Signing authority and key material
- Principal and tenant identity
- Capability scope and delegation lineage
- Approval integrity
- Replay, use-budget, and revocation state
- Authorization decision integrity
- Audit-chain integrity and availability
- Protected resources reached after an allow decision
- Confidential request context

## Actors

- Human administrators and approvers
- Legitimate AI agents and services
- Compromised agents or services
- Malicious tenant users
- External attackers with network access
- Insiders with administrative access
- Operators responsible for identity, policy, and incident response

## Trust boundaries

1. Administrative API authentication
2. Capability issuer and signing-key boundary
3. Capability token crossing an untrusted client or network
4. Authorization-state boundary
5. Human-approval boundary
6. Protected-resource enforcement point
7. Audit persistence and external anchoring boundary

## Primary threats and controls

| Threat | Example | Reference control | Residual risk |
|---|---|---|---|
| Principal spoofing | One agent claims another agent’s identity | Capability subject and request principal must match exactly | Bootstrap identity still depends on external authentication |
| Cross-tenant access | An agent presents authority from another tenant | Tenant is present in principal, capability, intent, and decision checks | Tenant provisioning and lifecycle are outside this repository |
| Wrong-service replay | A token issued for one service is used at another | Audience binding | Service must actually enforce the audience decision |
| Excessive authority | An agent receives broad actions or resources | Explicit closed actions and exact or terminal-prefix resources | Issuer can still grant excessive root authority |
| Delegation amplification | A child adds scope or lifetime | Monotonic delegation validation and parent-budget reservation | Distributed implementations need atomic reservation |
| Token tampering | Payload scope is edited | HMAC-SHA256 over header and canonical payload; constant-time verification | Shared HMAC key lets any verifier mint tokens |
| Duplicate-key ambiguity | JSON parsers interpret duplicated fields differently | Duplicate keys are rejected | Other encodings require equivalent canonicalization rules |
| Expired authority | Old authority is reused | Not-before and expiration checks | Trusted time and clock-skew policy are deployment concerns |
| Request replay | A previously allowed operation is resubmitted | Unique request identifier stored on successful authorization | HTTP ledger is durable and capacity-limited; library memory store remains local |
| Use-budget amplification | Parent and child both spend the full parent budget | Child budget is reserved from the parent | Durable distributed ledgers need strong consistency |
| Approval substitution | Approval for one action authorizes another | Approval binds to a fingerprint of actor, tenant, audience, action, resource, and context | External approver authentication is a separate control |
| Approval replay | One approval is used repeatedly | Approval expiration and maximum-use count | HTTP approval state survives restart; stale backups require controlled recovery |
| Revoked-child survival | Parent is revoked but child continues | Registered descendant revocation cascade | Children unknown to the local state cannot be discovered |
| State exhaustion | Replay ledger reaches capacity | Fail-closed `state_unavailable` decision | A production store needs capacity planning and backpressure |
| Policy bypass | Client ignores a deny decision | API returns explicit deny and audits the event | Enforcement must occur at or before the protected tool boundary |
| Sensitive-data logging | Tokens or private context enter audit logs | Tokens and signing keys are excluded; context is hashed | Resource names and reason codes may still require classification |
| Audit tampering | Decision history is edited | Existing hash-chained audit verification | Local chain does not prove completeness or prevent total deletion |
| Administrative compromise | Shared API token is stolen | Constant-time bearer-token verification and rate/body limits | Shared token is a bootstrap control, not production IAM |

## Abuse cases

### Compromised planning agent delegates broad payment authority

The child request is rejected when it adds actions, broadens resource prefixes,
extends lifetime, removes approval, changes tenant or audience, relaxes context,
or exceeds the parent’s remaining use budget.

### Malicious retrieved content asks the agent to reuse an old request

A previously successful request identifier returns `replay_detected`. The
protected service must treat every non-`allow` reason as a hard denial.

### Polished agent output requests an unauthorized tool

Model fluency is irrelevant. The action and resource must appear inside the
verified capability scope, and every contextual and approval condition must
match.

### Administrator revokes a parent after suspected compromise

The reference state records the parent and registered child relationship and
revokes the reachable descendant set. Production systems require a persistent,
queryable delegation graph and tested propagation guarantees.

### Attacker edits a capability payload

Any payload change invalidates the HMAC. Unknown key identifiers, malformed
base64url data, invalid JSON, duplicate keys, and schema violations fail closed.

## Security assumptions

- The Python process and interpreter are not already compromised.
- The signing key is generated with sufficient entropy and kept outside source
  control, logs, URLs, and client-side code.
- The protected resource calls the authorization control plane before executing.
- Administrative API authentication is enforced over authenticated transport.
- Tenant and principal enrollment are performed by a trusted external process.
- System time is sufficiently accurate for the configured token lifetime.

## Residual risks

### Symmetric signing

The reference HMAC design makes the protocol inspectable with the standard
library, but every verifier holding the key can mint authority. Production
systems should prefer asymmetric signatures or a remote signing service with
managed and hardware-backed keys.

### State persistence and recovery

The HTTP API persists revocation, approvals, replay markers, descendant relationships
and use counts in a required single-host ledger. Direct library examples can still
use process-local memory. Multi-host scaling requires a reviewed transactional store
and explicit partition behavior; restoring old backups requires containment and
signing-key rotation because later revocations or consumption may be absent.

### Root issuance policy

Aegis prevents delegated privilege escalation. It cannot determine whether a
human administrator should have issued an overly broad root capability.
Organizations still need role engineering, policy review, separation of duties,
and periodic access review.

### Enforcement placement

An authorization decision has value only when the protected tool, API, or
workflow refuses to operate without it. The final enforcement point must not be
controlled by the same untrusted agent requesting access.

### Audit completeness

The existing hash chain detects alteration of retained records. It does not prove
that every event was recorded, prevent loss of the entire log, or establish an
external timestamp. Production systems should stream to independently controlled
append-only storage and anchor digests outside the process.

## Verification strategy

- Unit tests exercise token tampering and wrong-key behavior.
- Scope tests cover principal, tenant, audience, action, resource, and context.
- Temporal tests cover early and expired authority.
- Stateful tests cover replay, use exhaustion, approval reuse, delegation
  reservation, and revocation cascade.
- API tests confirm administrative authentication and end-to-end decisions.
- CI runs static typing, architecture checks, branch coverage, Bandit,
  dependency auditing, CodeQL, and a non-root container build.

## Production review checklist

- [ ] Replace shared administrative token with federated identity.
- [ ] Replace HMAC issuer with managed asymmetric signing.
- [ ] Define key rotation, compromise, and verification-overlap procedures.
- [ ] Persist revocation, replay, approval, use, and delegation state.
- [ ] Define clock skew and maximum capability lifetime.
- [ ] Enforce authorization at each protected tool boundary.
- [ ] Classify and redact audit fields.
- [ ] Anchor audit evidence externally.
- [ ] Test partial outages and state-store partitions.
- [ ] Establish break-glass access with approval, expiry, audit, and review.
- [ ] Perform independent threat modeling and penetration testing.

## Durable HTTP ledger update

The HTTP API now requires [durable authorization state](DURABLE_AUTHORIZATION.md).
The memory-store limitations above remain relevant to direct library usage, not the
new HTTP default. API workers on one host share issuance registration, revocations,
replay markers, delegation budgets and approval use counts transactionally. New or
missing ledgers do not silently recreate authority. Host compromise, stale-backup
rollback, multi-host coordination and independent audit retention remain operational
risks; durable storage does not prove human presence or protect a compromised issuer.
