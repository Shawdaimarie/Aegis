# Durable authorization foundation

The Sentinal HTTP API now uses a mandatory SQLite authorization ledger. Revocations,
request replay markers, capability usage, delegation relationships and reservations,
and exact-intent approvals and their consumption counts survive process restarts.
Library examples can still use the separate in-memory reference store.

## Provisioning and rollout

Use a private directory on durable local storage, owned by the service operator.
Initialize a **new** ledger once with:

```sh
python -m aegis.adapters.authorization_store /absolute/private/path/authorization.sqlite3
```

Set `AEGIS_AUTHORIZATION_DB_PATH` to that file and keep `AEGIS_CONTROL_DB_PATH` pointing
to a **different** file for Admin Governance switches. Configure the same two files
for every worker on the host. Startup rejects absent authorization configuration,
missing/uninitialized/corrupt ledgers, unsupported schema versions and the same path
for both databases. Runtime opens existing ledgers only and returns a generic 503
when required state is unavailable. Initialization never overwrites an existing file.

This is a breaking startup requirement for older deployments. Pause automation,
stop old workers, back up their available evidence, initialize the ledger, rotate
signing credentials under an approved rollout, and issue new capabilities through
the new API. Do not import tokens into an empty ledger by trusting their signatures
alone. Tokens minted before issuance registration are deliberately not authorized.
No migration or credential rotation is performed automatically by this change.

## Transaction guarantees

A root capability is registered before its signed token is returned. Delegation
reserves parent budget and registers the child in the same transaction. Revocation
marks the root and all registered descendants atomically. Approval records cannot
be overwritten to reset their usage. Each successful consumption commits the replay
marker, capability use count and approval use count together; failures roll back.
Expiry is checked again inside the consumption transaction after waiting for locks.

Independent database connections use `BEGIN IMMEDIATE`, foreign-key enforcement and
full synchronous writes. SQLite serializes writers, including writers in different
processes sharing the same local database. See [SQLite isolation](https://www.sqlite.org/isolation.html).
The configured replay capacity defaults to 100,000 accepted request IDs; reaching it
blocks new consumption instead of silently evicting replay protection.

A running store detects replacement by a newly initialized ledger identity. Even a
new process cannot authorize old tokens against an empty replacement ledger because
its issuance registry lacks those capabilities. This is not tamper resistance against
a host administrator who can rewrite the database and possesses signing credentials.

## Recovery, limits and operations

- Keep the ledger, its journal files and switch database on supported durable local
  storage; do not put SQLite on a network filesystem or use one copy per worker.
- Back up with SQLite's consistent backup API, not a casual copy of a live database.
  See [SQLite backup guidance](https://www.sqlite.org/backup.html). Test recovery in an
  isolated environment and verify revocations, replay and use budgets before release.
- A backup is a snapshot. Restoring an older snapshot can lose later revocations and
  consumption. Keep automation paused, stop all workers and rotate signing keys to
  invalidate outstanding tokens before an approved rollback/reissue process. A ledger
  identity check cannot detect every rollback to an older copy with the same identity.
- Monitor storage, lock waits, request-capacity exhaustion and 503/denial rates. No
  automated deletion or retention policy is implemented; do not truncate state to
  clear capacity. Plan reviewed maintenance and capability expiry/key rotation.
- This is a single-host durable foundation, not distributed consensus or unlimited
  throughput. Plan a transactional database migration before multi-host deployment.
- The existing governance audit is still in-memory. Durable state is not an independent,
  externally anchored audit trail; that remains separate production work.
- Human/workload identity, phishing-resistant authentication, secret custody, executor
  cancellation and protected releases remain necessary. There is no IBM, Apple or MIT
  endorsement or certification claim.

Regression evidence covers API restarts, independent processes competing for one
budget, parallel delegation, replay capacity, approval consumption, cascade revocation,
transaction rollback, expiry, missing/corrupt/replaced storage and consistent backups.
The identity contract suite also runs against both storage implementations.
