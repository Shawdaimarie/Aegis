# Aegis

**Zero-trust identity, delegated authorization, and governance for AI agents.**

[![CI](https://github.com/Shawdaimarie/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Shawdaimarie/Aegis/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Shawdaimarie/Aegis/actions/workflows/codeql.yml/badge.svg)](https://github.com/Shawdaimarie/Aegis/actions/workflows/codeql.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](aegis/LICENSE)

AI agents should not receive ambient authority merely because they can produce a
plausible request. Aegis is a reference control plane that makes identity,
delegation, approval, authorization, replay protection, operational boundaries,
and audit evidence explicit before an agent affects a protected system.

The implementation lives in [`aegis/`](aegis/).

## What Aegis demonstrates

| Capability | Inspectable evidence |
|---|---|
| Typed identity | Human, agent, and service principals scoped to a tenant |
| Short-lived authority | Signed capabilities with audience, action, resource, time, context, and use constraints |
| Safe delegation | Child capabilities cannot broaden parent authority |
| Human approval | Approval artifacts bind to the exact authorization-intent fingerprint |
| Replay and budget control | Request identifiers, maximum uses, parent-budget reservation, and fail-closed exhaustion |
| Revocation | Parent revocation cascades to registered descendants |
| Runtime decisions | Deny-by-default allow/deny results with stable reason codes |
| Auditability | Issuance, delegation, approval, revocation, and decisions enter a hash-chained audit log |
| Governed AI operations | Existing training runs remain bounded by immutable lifecycle policies and reproducible manifests |
| Delivery discipline | Ruff, strict mypy, import contracts, branch coverage, Bandit, pip-audit, CodeQL, and non-root Docker |

## Architecture

```text
human / service / agent identity
              │
              ▼
      administrative issuance
              │
              ▼
 signed short-lived capability ──> optional narrower delegation
              │                              │
              └──────────────┬───────────────┘
                             ▼
                  authorization request
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
 identity + tenant     action + resource     time + context
 audience binding      scope evaluation      approval + budget
       └─────────────────────┼─────────────────────┘
                             ▼
              atomic replay / use enforcement
                             │
                    allow or stable deny
                             │
                             ▼
                  hash-chained audit record
```

## Security invariants

1. **Default deny.** Missing, malformed, expired, revoked, mismatched, replayed,
   exhausted, or insufficiently approved authority does not execute.
2. **No privilege amplification.** Delegation cannot add actions, broaden
   resources, change tenant or audience, extend lifetime, remove approval,
   relax context, or increase the remaining use budget.
3. **Approval is operation-specific.** A human approval for one actor, action,
   resource, audience, tenant, and context cannot authorize another operation.
4. **State transitions are auditable.** Capability and authorization events are
   recorded without storing the capability token or signing key.
5. **Reference boundaries are explicit.** The HMAC issuer and in-memory state are
   intentionally documented as development components, not production identity
   infrastructure.

## Quick start

```bash
cd aegis
uv sync --all-extras

export AEGIS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AEGIS_CAPABILITY_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

make check
make identity-demo
make serve
```

Open:

- API documentation: `http://127.0.0.1:8000/v1/docs`
- Governance console: `http://127.0.0.1:8000/console/`
- Health probe: `http://127.0.0.1:8000/healthz`

## Reviewer path

1. Read the [agent identity control-plane design](aegis/docs/AGENT_IDENTITY_CONTROL_PLANE.md).
2. Review the [identity threat model](aegis/docs/THREAT_MODEL_AGENT_IDENTITY.md).
3. Inspect the [typed contracts](aegis/src/aegis/identity/models.py),
   [signed capability codec](aegis/src/aegis/identity/capability.py),
   [state engine](aegis/src/aegis/identity/state.py), and
   [control plane](aegis/src/aegis/identity/control_plane.py).
4. Run the [identity unit tests](aegis/tests/identity/) and
   [API tests](aegis/tests/api/test_identity_v1.py).
5. Inspect CI, CodeQL, dependency automation, the standards crosswalk, and the
   explicit residual-risk statements.

## Relationship to Sentinel

[Sentinel](https://github.com/Shawdaimarie/sentinel) evaluates whether AI-agent
behavior is correct, safe, grounded, efficient, and reproducible. Aegis controls
who or what may act, on whose behalf, against which resource, under which
approval, and for how long. Together they demonstrate both **behavioral
assurance** and **runtime authority control**.

## Standards orientation

Aegis is informed by zero-trust architecture, secure software-development,
agent identity, and agent-security guidance. The project includes an engineering
crosswalk, but it does not claim certification or universal compliance.

## Scope and limitations

Aegis is a reference implementation. A consequential deployment still needs
federated workload identity, asymmetric signatures, managed or hardware-backed
keys, durable and strongly consistent revocation/replay state, external audit
anchoring, policy administration, incident response, privacy review, and
independent security assessment.

## License

Apache-2.0. See [`aegis/LICENSE`](aegis/LICENSE).
