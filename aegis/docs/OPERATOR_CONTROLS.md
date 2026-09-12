# Independent human controls

The console at `/console/` has two independent switches, saved per tenant:

| Switch | On | Off | New-tenant default |
| --- | --- | --- | --- |
| Automation | New capability authorization decisions may allow actions within policy | New action authorization decisions deny with `automation_paused` without consuming use budgets | Off |
| Require human approval for every action | Every otherwise allowed capability action needs an exact-intent approval | The signed capability's own approval requirement still applies | On |

Neither switch disables authentication, scope checks, revocation, replay detection,
use budgets or governance policy. Turning automation off does not cancel already
running actions or invalidate decisions already returned. Real executors must check
immediately before side effects and implement their own cancellation mechanism.
These controls apply to `/v1/authorization/check`, not synthetic training simulations
or external systems that do not call this API. Issuance, inspection and revocation
remain available while paused. Direct library callers remain trusted integration code.

## Who can use them

Operators are registered in trusted server configuration, never by a request body.
Each identity belongs to exactly one tenant. An admin can change both switches in
that tenant. A user or `authorized_personnel` identity can change only explicitly
assigned settings. An identity with no permissions can only read its tenant's settings
and control history. There is no implicit cross-tenant admin power.

`AEGIS_CONTROL_OPERATORS` contains a JSON array of records with these fields:

- `subject`: registered human identifier, such as `human:owner`;
- `tenant`: assigned tenant, such as `acme`;
- `role`: `admin`, `user`, or `authorized_personnel`;
- `token_sha256`: lowercase SHA-256 digest of a unique, cryptographically random personal
  bearer credential, generated with at least 32 random bytes and delivered securely;
- `permissions`: for users/personnel, zero or more of `automation_enabled` and
  `require_human_approval`. Admins implicitly have both within their tenant.

Do not reuse the service API token or approval token. Configurations with duplicate
credential hashes, invalid records, or service/reviewer credential reuse fail closed.
Remove an operator record to revoke switch access; mappings are checked on each request.
Do not put credentials in URLs, source control, logs or reason text. The console holds
its control credential only in memory and clears it on disconnect or page exit.

This bearer mapping is a reference integration, not phishing-resistant MFA or proof
of human presence. Replace it with a reviewed identity-provider integration for
production; preserve server-owned tenant and permission checks.

## Storage and API

Set `AEGIS_CONTROL_DB_PATH` to an absolute SQLite file path inside an existing,
operator-owned private directory. Use the same durable local volume/path for all
processes on the host. The service creates its tables; new tenants start paused with
approval required. Missing configuration, unreadable storage or corrupt settings
return 503; authorization is blocked. Back up the database and protect its directory.
Do not use SQLite on a network filesystem or give agents write access to the database.

- `GET /v1/controls`: current settings, revision, identity and permitted switches.
- `PATCH /v1/controls`: one `setting`, Boolean `enabled`, integer `expected_revision`,
  and a meaningful `reason` (3–256 characters). Tenant and actor come from authentication.
- `GET /v1/controls/history`: last 100 changes for that tenant only.

Every accepted change and its before/after values, actor, role, reason and UTC time
commit in the same transaction. If audit insertion fails, the change rolls back.
Conflicting edits return 409; reconnect and review before retrying. The browser never
optimistically claims an unconfirmed change succeeded. Changes serialize with new
authorization decisions across processes sharing the same SQLite file.

Settings and their change history survive application restarts. This does **not**
make the separate in-memory capability revocations, replay identifiers, approvals or
use budgets durable. Those remain production blockers from the authentication review.
Database owners can alter local history: independent audit retention is still needed.
The switch history is distinct from the existing in-memory governance audit tab.

## Verification

Python regressions cover safe defaults; independent operation; admin, user and staff
permissions; invalid credentials/configurations; tenant isolation; stale concurrent
updates; strict input validation; restart persistence; missing/corrupt storage; atomic
audit failure; authorization pause; mandatory approval; and signed approval requirements
remaining active when the global approval switch is off.

Run `node --test tests/web/controls.test.cjs` for console interaction regressions.
Browser verification also exercised both switches and a user restricted to automation.
No production settings or accounts were changed during development.
