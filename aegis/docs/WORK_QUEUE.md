# Persistent work queue and read-only GitHub inspection

Sentinal now supports one bounded workflow: save a repository inspection request,
review it as a named human, explicitly run it as an authorized operator, and retain
its metadata report. It does not generate fixes, execute repository code, create
branches or open pull requests. Those need separate exact-change approval and execution.

## Explicit setup

The feature is disabled until separately configured. Existing operator roles receive
no new workflow permission automatically, including admins.

1. Provision a new private queue on durable local storage:
   `python -m aegis.adapters.work_queue /absolute/private/path/work.sqlite3`.
   Initialization refuses an existing file. Runtime never recreates missing storage.
2. Set `AEGIS_WORK_DB_PATH` to that file, separate from the authorization and control
   databases. All workers on one host must share the same three files.
3. Set `AEGIS_GITHUB_REPOSITORIES` to a trusted tenant mapping, for example
   `{"your-tenant":["Shawdaimarie/Aegis"]}`. This is an example, not activated policy.
4. Add `"workflows":["github.inspect"]` only to approved named entries in
   `AEGIS_CONTROL_OPERATORS`. The operator's tenant comes from this trusted mapping.
5. Supply `AEGIS_GITHUB_READ_TOKEN` through server secret configuration, never the
   browser. Use an appropriately scoped, read-only GitHub App installation token or
   supported fine-grained credential for selected repositories. Token refresh and
   provisioning are operator responsibilities; this feature does not mint credentials.
6. Configure the existing separate reviewer identity. To run approved work, an
   authorized operator must also enable the tenant's Automation switch.

Relevant API references: [repository metadata](https://docs.github.com/en/rest/repos/repos#get-a-repository)
and [commit lookup](https://docs.github.com/en/rest/commits/commits#get-a-commit).

## Authority and state transitions

Submission persists an immutable repository, purpose, request key and authenticated
requester. It grants no execution authority. The same tenant/request key deduplicates
an identical retry; a different request or actor using that key receives a conflict.
Request bodies cannot supply tenant, reviewer, status, workflow commands or results.

A reviewer lists their own tenant's saved requests and records approve/reject with a
reason and expected revision. Approval lasts five minutes. A reviewer can withdraw an
unused approval by rejecting the current revision. Decisions and state transitions
are recorded with attributed full snapshots in a separate events table in the same
transaction. This is local durable history, not an independently anchored audit.

An operator explicitly runs approved work. Permission, repository allowlist and the
Automation switch are checked before the transactional claim. Approval is always
required for this workflow, even when the broader human-approval switch is off. Only
one caller can claim an approved item. Turning Automation off prevents new claims;
it does not cancel a request already claimed and in progress.

States: pending -> approved -> running -> succeeded or failed; pending or approved
can become rejected. There is no automatic retry or transition from running back to
approved. If a process dies after claiming, the item remains running for investigation.
A finished HTTP response can be lost; refresh saved work before deciding what happened.
Read-only GETs may have occurred before an interrupted process lost its report.

This workflow uses its own narrowly defined queue approval; it does not issue or consume
capability tokens from the general Action Review API. It cannot execute arbitrary actions.

## Connector boundary and report meaning

The connector sends only HTTPS GETs to the fixed api.github.com host. It does not follow
redirects, accept caller-selected hosts, retry automatically or execute source content.
Each response is limited to 1 MiB and connections have a ten-second socket timeout.
The token is in the request header, never a URL, job record or returned error.

The report retains the repository identity, observed default branch and commit SHA,
archived/visibility status and open issue count. Metadata and commit are fetched in
separate requests; the branch can change afterward. GitHub's open issue count can include
pull requests. This report is not a code audit or proof of secure repository settings.
Missing access, rate limits, unexpected data and transport failures produce a generic
failed result, preserving no raw upstream error. Live API integration has not been
verified with a deployment credential in this change.

## Capacity, recovery and future work

The first interface shows the latest 100 tenant requests. Storage stops accepting new
work at 10,000 total items. Pagination, archival and tenant capacity quotas remain future
work. No records are automatically deleted to clear capacity. Plan reviewed maintenance
before reaching these limits.

Use consistent SQLite backups. Restoring a stale queue can restore an unused approval:
pause Automation, stop workers, verify the snapshot and wait beyond all restored approval
expirations before an approved restart. Treat interrupted running jobs as unresolved;
investigate and submit fresh work for fresh approval if another inspection is needed.
There is no automatic lease recovery or multi-host scheduling.

Passkeys, identity-provider integration, session recovery, independent audit retention,
a production GitHub App connection and the draft-PR workflow remain unfinished. The
current named credential mappings do not prove physical human presence.

## Verification

Tests cover durable reload/restart, request deduplication, reviewer/tenant isolation,
stale revisions, withdrawal, expiry, concurrent claims, automation pause, allowlist
removal, missing/corrupt storage, connector identity/URL boundaries and generic failures.
Browser verification used disposable local credentials and a clearly labeled synthetic
report: request -> review -> run -> saved result -> reload. No live GitHub call or code
change occurred in that browser test. Desktop and 390-pixel mobile layouts had no page
horizontal overflow; the test produced no browser console errors.
