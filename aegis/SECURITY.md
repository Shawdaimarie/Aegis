# Security policy

## Reporting

Report suspected vulnerabilities privately to the repository owner. Include the
affected component, reproduction steps, impact, and any available mitigation.
Do not place credentials, private data, or exploitable details in a public issue.

## Security posture

Aegis is a reference implementation for governed AI operations and zero-trust
agent authorization. It is not a certification, managed identity provider, or
complete production security boundary.

The engineering target is informed by OWASP ASVS, NIST SP 800-207 zero trust,
NIST SP 800-218 secure software development, the NIST AI Risk Management
Framework, and agent-security guidance. Control applicability remains deployment
specific.

## Controls in this codebase

| Threat | Control | Evidence |
|---|---|---|
| Administrative spoofing | Bearer-token bootstrap with constant-time comparison | `src/aegis/api/v1/security.py` |
| Agent or service spoofing | Signed capabilities bind exactly one typed subject | `src/aegis/identity/capability.py` |
| Cross-tenant access | Principal, capability, and request tenant checks | `src/aegis/identity/models.py`, `control_plane.py` |
| Wrong-service use | Explicit audience binding | `src/aegis/identity/control_plane.py` |
| Excessive agency | Action, resource, time, context, approval, and use constraints | `src/aegis/identity/` |
| Delegation escalation | Monotonic child-scope validation and parent-budget reservation | `src/aegis/identity/capability.py`, `state.py` |
| Token tampering | Canonical payload, HMAC-SHA256, duplicate-key rejection, constant-time comparison | `src/aegis/identity/capability.py` |
| Replay | Successful request identifiers enter a bounded replay ledger | `src/aegis/identity/state.py` |
| Approval substitution | Approval binds to the exact authorization-intent fingerprint | `src/aegis/identity/control_plane.py` |
| Revoked-child survival | Parent revocation cascades through registered descendants | `src/aegis/identity/state.py` |
| Policy bypass | Deny-by-default reasoned decision before protected execution | `src/aegis/identity/control_plane.py` |
| Audit tampering | Hash-chained audit log verified before read | `src/aegis/governance/audit.py` |
| Information disclosure | Tokens and signing keys excluded from audit; request context hashed | `src/aegis/identity/control_plane.py` |
| Denial of service | Body limit, per-client rate limit, bounded token and state inputs | API middleware and Pydantic models |
| Supply-chain compromise | Ruff, strict mypy, import contracts, Bandit, pip-audit, CodeQL, Dependabot, non-root container | `.github/`, `pyproject.toml`, `Dockerfile` |

## Secrets

Required runtime secrets:

```text
AEGIS_API_TOKEN
AEGIS_CAPABILITY_SIGNING_KEY
```

Generate independent high-entropy values. Do not commit them, place them in
URLs, expose them to browser code, or reuse them across environments. Production
systems should store issuer keys in a managed key service or HSM and should use
asymmetric verification so authorization services cannot also mint authority.

## Dependency and build security

- Dependencies are resolved from `pyproject.toml` and should be locked before a
  production release.
- `pip-audit` checks known Python dependency vulnerabilities.
- Bandit and CodeQL inspect source for common security defects.
- Dependabot proposes dependency and GitHub Actions updates.
- The container runs as a non-root user.
- Production base images and external actions should be pinned by digest or full
  commit SHA after an organization defines its update procedure.

## Known limitations

- Capability signing uses a reference HMAC codec.
- Replay, revocation, approval, delegation, and use state are process-local.
- The administrative API uses a shared bearer-token bootstrap.
- The local audit chain does not prove log completeness or prevent total loss.
- Tenant and principal enrollment are external responsibilities.
- Protected resources must enforce the returned decision outside the requesting
  agent’s control.

See [`docs/THREAT_MODEL_AGENT_IDENTITY.md`](docs/THREAT_MODEL_AGENT_IDENTITY.md)
for detailed abuse cases, assumptions, and production migration requirements.

## Updated authority boundary

See [authenticated human approval](docs/HUMAN_APPROVAL_BOUNDARY.md) for the enforced separate-credential path, fixed service identity, and deployment limitations. CodeQL results are retained as private CI artifacts; managed dashboard upload is not enabled.
