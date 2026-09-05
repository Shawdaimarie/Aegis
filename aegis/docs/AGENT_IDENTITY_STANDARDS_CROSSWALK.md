# Agent Identity Standards Crosswalk

This document maps Aegis engineering controls to established and emerging
security guidance. It is a design crosswalk, not a certification, attestation,
or claim of complete compliance.

## NIST SP 800-207: Zero Trust Architecture

| Zero-trust concept | Aegis implementation | Boundary |
|---|---|---|
| No implicit trust based on network location | Every protected request requires a verified capability and explicit authorization decision | Transport and service identity remain deployment responsibilities |
| Per-request access decision | `/v1/authorization/check` evaluates each operation | Protected systems must enforce the decision |
| Dynamic policy inputs | Tenant, principal, audience, action, resource, time, context, approval, replay, revocation, and budget are evaluated | Reference context matching is exact-key equality, not a general policy language |
| Least privilege | Closed action sets, bounded resources, short lifetime, and use counts | Root issuer policy remains an organizational control |
| Continuous evaluation | Every request is re-evaluated and audited | The reference state is process-local |
| Policy decision and enforcement separation | Aegis returns a decision; protected tools should enforce it outside the requesting agent | A production PEP integration is not included |

## NIST AI Risk Management Framework

| Function | Aegis evidence |
|---|---|
| GOVERN | Explicit owners, reason codes, documented boundaries, reviewable policy and threat model |
| MAP | Principal, tenant, audience, resource, delegation, approval, and trust-boundary models |
| MEASURE | Tests for tampering, temporal validity, replay, scope, approval, delegation, and revocation |
| MANAGE | Deny-by-default decisions, short lifetime, use budgets, revocation, audit, and production migration requirements |

## NIST AI Agent Standards Initiative and agent-identity work

Aegis addresses several engineering questions emphasized by current agent
identity and authorization work:

- distinguishing human, agent, and service principals;
- binding an agent to a tenant and intended audience;
- expressing delegated authority in a portable, inspectable envelope;
- preventing delegation from increasing privilege;
- preserving lineage and revocation relationships;
- requiring operation-specific human approval when configured;
- emitting stable decision and audit evidence; and
- keeping the evaluator independent of model fluency.

Aegis does not define a universal agent identity standard. It provides a concrete
reference implementation that can be compared with future profiles and
interoperability requirements.

## OWASP agentic and LLM security guidance

| Agent-security concern | Aegis control |
|---|---|
| Excessive agency | Explicit action/resource scope, use budget, expiration, and approval |
| Tool misuse | Protected operations require an allow decision at the tool boundary |
| Identity and privilege abuse | Typed principals, audience binding, tenant binding, monotonic delegation |
| Indirect prompt injection | Retrieved instructions cannot grant capability scope or bypass authorization |
| Sensitive-data exposure | Capability tokens and signing keys are excluded from audit; context is fingerprinted |
| Unsafe autonomous action | Approval-required capabilities bind a human decision to the exact operation |
| Repudiation | Issuance, delegation, approval, revocation, allow, and deny events are hash chained |
| Replay | Successful request identifiers are recorded and reused identifiers fail closed |

Aegis complements, rather than replaces, model-behavior evaluation. Sentinel can
measure whether an agent follows instructions and avoids unsafe behavior; Aegis
controls whether the agent possesses authority to act.

## NIST SP 800-218: Secure Software Development Framework

| Practice | Repository evidence |
|---|---|
| Prepare the organization | CODEOWNERS, explicit architecture, issue scope, threat model, and security policy |
| Protect the software | Least-privilege workflows, non-root container, dependency automation, and no committed secrets |
| Produce well-secured software | Strict schemas, deny-by-default implementation, focused security tests, Ruff, strict mypy, Bandit, pip-audit, and CodeQL |
| Respond to vulnerabilities | Security reporting policy, stable reason codes, revocation path, and documented incident controls |

## OAuth and capability-security principles

Aegis is not an OAuth authorization server. The implementation nevertheless
adopts relevant security principles:

- audience restriction;
- short-lived bearer material;
- explicit scope;
- token integrity validation;
- replay-sensitive request identifiers;
- key identifiers for rotation planning;
- narrow delegation; and
- rejection of malformed or ambiguous payloads.

A production web ecosystem may use OAuth 2.x, token exchange, proof-of-possession,
OIDC, workload identity, or another standardized mechanism. Aegis’s internal
capability model should then sit behind or map to that protocol rather than
inventing a competing federation layer.

## SLSA and software supply-chain orientation

The repository does not claim a SLSA level. It does provide:

- version-controlled source and workflows;
- repeatable dependency resolution;
- automated tests and static analysis;
- package and container build gates;
- dependency update automation; and
- reviewable pull-request history.

Future hardening should add signed provenance, SBOM generation, pinned action and
base-image digests, protected environments, and release verification.

## Production gaps to close

The reference implementation intentionally leaves these capabilities for future
work:

1. Federated human and workload identity
2. Asymmetric or remote signing and verifier key distribution
3. Durable distributed revocation and replay state
4. Policy administration, simulation, and rollout controls
5. Delegation-graph persistence and access review
6. Proof-of-possession or channel binding
7. External audit anchoring
8. Multi-region consistency and outage semantics
9. Privacy classification and retention enforcement
10. Independent assessment and organization-specific control validation

## Review rule

A control may be described as aligned with a cited principle only when the
repository contains inspectable implementation or documentation evidence. Aegis
must not be described as NIST-certified, OWASP-certified, OAuth-compliant, or
universally secure.
