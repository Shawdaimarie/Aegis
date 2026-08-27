# Runbook: a run was HALTed

1. Identify the boundary: the API `outcome` field or exception names it (e.g. `halt:gpu-hours-ceiling`).
2. Verify the audit chain: `GET /v1/audit` must return `verified: true`. If false, treat as a
   security incident (SECURITY.md) before anything else.
3. Inspect the manifest attached to the exception; `governance_decisions` lists every advisory
   that preceded the halt.
4. Decide whether the fix is to the run (reduce compute, fix divergence) or to the boundary.
   Boundary changes go through `configs/governance/` by PR with two reviewers including the `owner`.
5. Never relaunch by editing the boundary file locally; the loosened value is itself audited.
