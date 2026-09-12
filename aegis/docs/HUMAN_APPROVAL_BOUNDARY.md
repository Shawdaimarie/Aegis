# Authenticated human approval boundary

The administrative API credential authenticates the fixed `api-client` service
principal. Request headers cannot choose the actor. Root issuance and revocation
requests must name that service identity; they cannot attribute an action to an
unverified human. Administrative credentials remain root authority and must never
be distributed to untrusted workloads.

The approval endpoint uses a separate credential and operator-owned identity mapping:

- `AEGIS_APPROVER_TOKEN`: a distinct secret kept under the human reviewer's control;
- `AEGIS_APPROVER_SUBJECT`: that reviewer's registered subject;
- `AEGIS_APPROVER_TENANT`: the tenant for which that reviewer can approve.

Approval is unavailable when any mapping is missing or when the approval credential
equals the service credential. An ordinary service token cannot approve. The request's
approver must exactly match the authenticated subject and tenant. A JSON field saying
`kind: human` does not authenticate anyone. The resulting approval remains bound to the
exact intent fingerprint, capability, expiry and use budget.

This is a reference credential mapping, not proof of physical human presence. Production
needs an identity provider, interactive human review, credential custody, revocation,
scoped operator roles, independent audit retention and executor-side enforcement.
The in-process library trusts its caller to supply authenticated principals; it is not
an authentication service. The HMAC issuer and in-memory state are not production identity.

The body limits, missing/non-finite measurement rejection and simulation controls from
the main-branch security PR are also included on this feature branch. Assertions about
source measurements and dataset hashes still require independent validation.

CodeQL runs analysis and saves SARIF as a private workflow artifact. Upload to GitHub's
managed code-scanning dashboard is disabled explicitly because that integration was
unavailable. Review the retained report; a completed scan is not a human approval.

Repository review controls remain proposed until GitHub settings are activated. See
the repository-root HUMAN_AUTHORITY.md. This branch is not deployed.

## Operator switches

[Independent human controls](OPERATOR_CONTROLS.md) adds server-enforced, tenant-scoped
automation and mandatory-approval switches. Settings and change history persist in
SQLite. Named control operators use separate credentials and assigned permissions.
New tenants start paused with approval required. Turning the global approval switch
off does not remove a signed capability's approval requirement. The underlying
capability ledger remains in-memory; this feature does not resolve that durability gap.
