# Rotate the capability signing key

## Purpose

Replace a capability-signing key without silently accepting tokens under an
unknown or compromised key. The reference implementation supports one active
key identifier per process; production systems should use a managed key ring and
a bounded verification-overlap window.

## Preconditions

- A named incident or planned rotation change exists.
- The operator has access to the deployment secret manager.
- The current key identifier and maximum capability lifetime are known.
- Revocation, audit, and rollback owners are available.
- No key material is copied into tickets, chat, source control, or logs.

## Reference deployment procedure

1. Stop issuing new capabilities from the affected instance.
2. Record the rotation reason and current audit head.
3. Generate a new high-entropy key in the deployment secret manager.
4. Change the configured key identifier in code or deployment configuration.
5. Replace `AEGIS_CAPABILITY_SIGNING_KEY` through the secret manager.
6. Restart the reference process so the new key is loaded.
7. Revoke capabilities issued under the previous key where their identifiers are
   known and the state remains available.
8. Run health, issuance, inspection, authorization, replay, approval, and
   revocation checks.
9. Confirm that a token signed under the old key fails with `invalid_token` or
   an unknown-key error.
10. Record the new deployment version, key identifier, test evidence, and audit
    head.

## Rollback

Rollback is appropriate only when the previous key is not suspected compromised.
Restore the previous secret and key identifier, restart, and repeat the full
verification sequence. Record why rollback was safer than continuing with the
new key.

## Compromise response

When compromise is suspected:

- do not restore or extend the old key;
- revoke reachable capability identifiers;
- stop protected operations when revocation completeness is uncertain;
- preserve audit and infrastructure evidence;
- rotate administrative credentials independently;
- investigate how key material was accessed;
- review every allow decision during the exposure window; and
- require explicit authorization before resuming consequential operations.

## Production migration

A production issuer should support:

- asymmetric signing;
- managed key versions;
- verifier-only public-key distribution;
- a defined overlap interval shorter than the maximum token lifetime;
- automated retirement after overlap;
- compromise revocation outside the application process; and
- externally anchored issuance and rotation audit evidence.
