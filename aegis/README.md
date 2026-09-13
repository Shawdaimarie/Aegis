# Aegis

**Zero-trust identity, delegated authorization, governance, and reproducible AI operations.**

Aegis is a reference platform for teams that need AI agents and training systems
to operate under explicit authority, immutable boundaries, reproducible inputs,
and reviewable audit evidence.

## Install and verify

```bash
uv sync --all-extras
make check
```

Run the identity demonstration:

```bash
make identity-demo
```

Start the API and console:

```bash
export AEGIS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AEGIS_CAPABILITY_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
# First setup only: initialization refuses to overwrite an existing ledger.
mkdir -p -m 700 .local-state
export AEGIS_AUTHORIZATION_DB_PATH="$PWD/.local-state/authorization.sqlite3"
export AEGIS_CONTROL_DB_PATH="$PWD/.local-state/controls.sqlite3"
uv run python -m aegis.adapters.authorization_store "$AEGIS_AUTHORIZATION_DB_PATH"
make serve
```

The API is available on port 8000, with OpenAPI documentation at `/v1/docs`,
the governance console at `/console/`, and the liveness probe at `/healthz`.

## Agent identity and authorization

Aegis issues signed, short-lived capability envelopes to typed human, agent, and
service principals. Authority is bound to:

- one tenant and audience;
- one subject;
- an explicit action set;
- exact or terminal-prefix resources;
- not-before and expiration times;
- a bounded use count;
- optional context constraints; and
- optional human approval.

Delegation is monotonic. A child capability cannot add actions, broaden
resources, change tenant or audience, extend lifetime, remove an approval
requirement, relax context constraints, or increase the parent’s remaining use
budget. Parent revocation cascades to registered descendants.

Authorization decisions return stable reason codes including:

```text
allow
invalid_token
not_yet_valid
expired
revoked
principal_mismatch
tenant_mismatch
audience_mismatch
action_denied
resource_denied
context_mismatch
approval_required
approval_invalid
use_budget_exhausted
replay_detected
state_unavailable
```

Every issuance, inspection, delegation, approval, revocation, allow, and deny
operation enters the existing hash-chained audit log.

Read:

- [`docs/AGENT_IDENTITY_CONTROL_PLANE.md`](docs/AGENT_IDENTITY_CONTROL_PLANE.md)
- [`docs/THREAT_MODEL_AGENT_IDENTITY.md`](docs/THREAT_MODEL_AGENT_IDENTITY.md)
- [`docs/AGENT_IDENTITY_STANDARDS_CROSSWALK.md`](docs/AGENT_IDENTITY_STANDARDS_CROSSWALK.md)

## Governed AI training

The existing training runner remains available. Every run executes under an
immutable set of operational boundaries, emits a content-addressed manifest,
and records governance decisions in the audit chain.

```bash
python scripts/run.py --config examples/independent.json --seed 42
```

Running the same configuration and seed produces the same manifest identifier.

## API surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/identity/capabilities` | Issue a root capability |
| `POST` | `/v1/identity/capabilities/delegate` | Issue a strictly narrower child capability |
| `POST` | `/v1/identity/capabilities/inspect` | Verify and decode a capability |
| `POST` | `/v1/identity/approvals` | Bind a human approval to one exact intent |
| `POST` | `/v1/identity/revocations` | Revoke a capability and descendants |
| `POST` | `/v1/authorization/check` | Return and audit an allow/deny decision |
| `GET` | `/v1/governance/boundaries` | Inspect immutable operational boundaries |
| `POST` | `/v1/governance/evaluate` | Evaluate a run context |
| `POST` | `/v1/runs/simulate` | Execute a governed synthetic run |
| `GET` | `/v1/audit` | Verify and read the audit tail |

Administrative endpoints still use the existing bearer-token boundary. In a
production deployment, bind administration and issuance to federated human or
workload identity rather than a shared token.

## Repository layout

```text
src/aegis/core             pure domain primitives
src/aegis/governance       operational boundaries and audit chain
src/aegis/identity         principals, capabilities, approvals, state, decisions
src/aegis/training         scenarios, runner, reproducibility manifest
src/aegis/adapters         environment, persistence, and I/O boundaries
src/aegis/api/v1           authenticated FastAPI control-plane surface
tests/identity             capability and authorization security tests
tests/api                  end-to-end API tests
docs                       architecture, threat model, standards, runbooks
examples                    reproducible demonstrations
```

## Quality and security gates

`make check` enforces:

- Ruff formatting and linting;
- architectural import contracts;
- strict mypy;
- documentation coverage;
- pytest with branch coverage;
- Bandit; and
- dependency vulnerability auditing.

GitHub Actions additionally builds the package and a non-root container image.
CodeQL and Dependabot are configured independently.

## Scope boundary

The HTTP API requires the [durable authorization ledger](docs/DURABLE_AUTHORIZATION.md).
The library retains an in-memory reference implementation for examples and tests.
The HMAC codec and single-host SQLite ledger are not substitutes for
asymmetric workload identity, managed key rotation, a hardware-backed issuer,
durable distributed revocation, or independent audit anchoring.

## Governing documents

[`STANDARDS.md`](STANDARDS.md) · [`SECURITY.md`](SECURITY.md) ·
[`docs/adr`](docs/adr) · [`docs/runbooks`](docs/runbooks)

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Human review setup

Live approvals are disabled until a separate operator-owned reviewer credential and identity are configured. See [the approval boundary](docs/HUMAN_APPROVAL_BOUNDARY.md). Do not send a service token or caller-supplied identity as proof of human approval.
