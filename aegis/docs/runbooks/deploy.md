# Runbook: first deployment

Prerequisite: the CI pipeline is green on `main`. Never deploy from a dirty tree.

## Generate independent secrets

Generate the administrative API token and capability-signing key independently.
Do not reuse either value across environments.

```bash
export AEGIS_API_TOKEN="$(openssl rand -base64 32)"
export AEGIS_CAPABILITY_SIGNING_KEY="$(openssl rand -base64 48)"
```

Store both values in the deployment secret manager. Do not place them in source
control, command history retained on shared systems, support tickets, or URLs.

## Fly.io

```bash
fly launch --no-deploy --copy-config
fly secrets set AEGIS_API_TOKEN="$AEGIS_API_TOKEN"
fly secrets set AEGIS_CAPABILITY_SIGNING_KEY="$AEGIS_CAPABILITY_SIGNING_KEY"
fly deploy
fly open /console/
```

`fly secrets list` displays secret names and digests, not recoverable values.

## Render

Push the repository to GitHub and create a Blueprint from `render.yaml`. Render
creates independent values for both required secrets. Use the service Environment
page to rotate them; do not expose the capability-signing key to the browser
console.

## Post-deployment verification

1. `GET /healthz` returns `{"status":"ok"}`.
2. `/version` reports API `v1` and the expected release version.
3. `/console/` loads, the administrative token connects, and boundaries render.
4. Run a simulation with `gpu_hours_per_step = 1000`; confirm the outcome is
   `halt:gpu-hours-ceiling`.
5. Issue a short-lived, one-use capability to a non-production test principal.
6. Inspect the capability through the authenticated API.
7. Authorize the declared action and confirm `allow` with zero remaining uses.
8. Replay the same request identifier and confirm `replay_detected`.
9. Revoke a separate test capability and confirm the next decision is `revoked`.
10. Read `/v1/audit`; confirm the chain verifies and includes the deployment
    smoke-test decisions without recording either secret or a full token.

Record the deployment URL, commit hash, test-capability identifiers, audit head,
and verification time in `docs/assessments/`. Delete or revoke test authority
before enabling consequential integrations.

## Rollback

Rollback only to an artifact with a green CI and CodeQL record. When a signing
key is suspected compromised, do not roll back to that key. Follow
[`rotate-capability-signing-key.md`](rotate-capability-signing-key.md) and keep
protected operations paused until authority can be re-established.
