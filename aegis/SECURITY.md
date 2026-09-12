# Security boundaries

This is a reference governance and synthetic-training service. Standards are design
goals, not certifications. No production deployment, signed-release pipeline, lockfile,
secret-scanning service, or external audit retention is established by this repository.

## Verified controls

- Bearer authentication uses constant-time comparison. The shared token identifies
  `api-client`; a caller-supplied header cannot impersonate a named human.
- Boundary configuration loads from operator-controlled files, not request payloads.
  Unknown keys are rejected. A missing numeric measurement for a blocking or halt
  boundary denies the evaluation; non-finite telemetry and thresholds are rejected.
- The API reads at most 256 KiB of body data, including requests without a truthful
  Content-Length. The server's simulation cap is 1,000 steps and cadence is fixed at one.
- Rate buckets expire and have a fixed population ceiling. Client-facing validation
  errors omit input values. Authentication configuration failures return a safe 503.
- An in-memory hash chain records evaluations and service identity. Hash verification
  detects internal alteration but does not authenticate a human or resist full rechaining.
- The security CI job runs lint, strict types, regression tests with a coverage floor,
  and a dependency vulnerability audit. GitHub Actions are pinned to exact revisions.

## Human authority and deployment requirements

See ../../HUMAN_AUTHORITY.md and the repository-root .github/CODEOWNERS. Proposed
rules require human approval; they are not active until GitHub settings are configured.
The current GitHub plan rejected private-repository ruleset access during this audit.

The evaluate endpoint judges supplied snapshots; a caller can lie about measurements
or dataset hashes. It is not proof of real execution, authentic source data, compliance,
or human approval. The simulation endpoint performs synthetic arithmetic, not trading,
external tool use, or network policy enforcement. Egress tags are declarations only.

Before deployment, authenticate individual users, enforce scopes and approvals at the
executor, collect trusted telemetry, bound audit retention and aggregate workload,
protect against slow requests at ingress, persist audit evidence independently, secure
the operator's configuration and secrets, and pin/audit deployment dependencies/images.
Rate limits are per process and trust the directly connected client address; a proxy
needs its own authenticated rate-limiting design. The in-memory audit log grows for
the process lifetime and is lost on restart. Do not claim production readiness.

## Reporting

Contact the repository owner through a private channel or GitHub private advisory if
enabled. Do not post credentials or exploit details to public issues.
