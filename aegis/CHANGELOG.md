# Changelog

## 0.2.0 - 2026-09-05

### Added

- Typed human, agent, and service principals scoped to one tenant.
- Signed short-lived capability envelopes with explicit key identifiers.
- Tenant, audience, principal, action, resource, temporal, context, approval,
  and use-budget authorization constraints.
- Monotonic delegation with parent-budget reservation and descendant revocation.
- Exact-intent human approvals, replay detection, and stable decision reason codes.
- FastAPI endpoints for capability issuance, delegation, inspection, approval,
  revocation, and authorization checks.
- Identity-control-plane unit and API security tests.
- Agent identity architecture, threat model, standards crosswalk, and end-to-end demo.
- Repository-level CI, CodeQL, Dependabot, and CODEOWNERS controls.

### Changed

- Aegis is positioned as a zero-trust agent identity, authorization, governance,
  and reproducible AI-operations reference platform.
- The verification gate now includes documentation coverage and example linting.
- Runtime deployment requires an independent capability-signing key in addition
  to the administrative API token.

### Security

- Capability tokens reject tampering, unknown key identifiers, malformed base64,
  duplicate JSON keys, unknown fields, and invalid scope.
- Approval cannot be substituted across actor, tenant, audience, action,
  resource, or context.
- A child capability cannot broaden parent authority or increase the remaining
  successful-use budget.
- The security policy now states the HMAC, in-memory state, shared administrative
  token, audit-completeness, and external-enforcement limitations explicitly.

## 0.1.0 - 2026-08-27

- Initial reference implementation: governance engine, hash-chained audit,
  training runner, manifests, v1 API, console, CI pipeline, standards, and
  security policy.
