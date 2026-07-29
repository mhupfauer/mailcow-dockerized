# Task 5 Authorization Lifecycle Remediation Design

## Goal

Close the two load-bearing Task 5 authorization gaps without changing the
OAuth schema or broadening the feature:

1. An unactivated reauthentication bridge must not survive client cleanup and
   restage authorization afterward.
2. Every fresh Session used to finalize stranded cleanup must be durably
   retained before provider cleanup, so failures remain retryable.

The repair continues to use the authenticated authorization state stored in
the existing `consents.scopes` envelope. It does not add a table, rotate the
account-wide authorization epoch for client-only cleanup, or implement the
Task 6 MCP transport.

## State transitions

### Entering client cleanup

`beginClientCleanup` continues to lock the account row and consent row in the
existing order. When the current state is `pending_reauth`, the same
transaction must:

- add the pending Session UID to the bounded cleanup Session set;
- add the pending bridge fingerprint and its original expiry to the bounded
  retired-bridge set;
- change the lifecycle to `cleanup_pending`; and
- clear the pending authority fields only after their cleanup evidence has
  been retained.

Retirement uses the existing authenticated, deterministic expiry pruning and
capacity rules. A live retired fingerprint is never evicted. If capacity is
exhausted, the transaction fails without changing authorization state.

After successful provider cleanup, `completeClientCleanup` may write
`revoked`, but it must preserve the live retired-bridge markers until their
normal expiry. Consequently, the old bridge cannot restage against the
client's revoked row even though client-only cleanup does not rotate the
account epoch.

### Joining a stranded cleanup

Add one repository operation that transactionally joins a current provider
Session to an existing `cleanup_pending` or `cleanup_finalizing` outbox. It
must:

- lock the account and consent rows using the established ordering;
- require the expected account, client, and resource;
- add the current Session UID to the bounded Session set without eviction;
- when a reauthentication bridge is present, verify its authenticated
  account/client/resource/epoch/expiry binding and retire its fingerprint;
- be idempotent for the same Session UID and bridge; and
- reject malformed, expired, rebound, capacity-exhausted, quarantined, active,
  or already-clean state without performing provider cleanup.

The interaction router must call this operation before attempting to destroy
any grant or Session for a fresh finalizer. The resulting stored state, rather
than the pre-join state, is the cleanup authority passed to provider cleanup.

## Cleanup completion and failures

Provider grant and Session cleanup remains strict: all requested revocations
and destroys may run concurrently, but any rejected provider operation makes
the cleanup attempt fail.

The database lifecycle may become `revoked` only after all authority recorded
in the durable cleanup state has been successfully removed from the provider.
If destroying the fresh current Session fails, the response remains a
no-store operational failure and the consent remains in cleanup state with
that Session UID retained. A later browser finalizer or account-wide
credential revocation must see and retry the same UID.

If provider cleanup succeeds but final database completion fails, the retained
cleanup state remains sufficient for an idempotent no-Session retry. Existing
validated cleanup return locations and zero-byte redirect behavior remain
unchanged.

## Concurrency and bounds

All new mutations run under the existing account/client/resource mutation
coordinator and database row locks. No operation silently evicts a live
Session UID or retired bridge marker. Existing maximum Session and bridge
limits remain the only bounds; exhaustion fails closed before external
provider mutation.

Account-wide revocation continues to invalidate the account epoch and prepare
all client states before provider cleanup. Because fresh finalizer Sessions
are now persisted, the account-wide revoker can neither overlook them nor
mark their client clean after a failed destroy.

## Tests

Add real-provider integration regressions that first fail against the current
implementation:

1. Stage a bridge but do not activate it, revoke the client, complete cleanup,
   then attempt to stage the same still-unexpired bridge. Staging must fail,
   and the raw consent row must not expose the fingerprint.
2. Enter `cleanup_finalizing`, authenticate a fresh finalizer, persist its new
   Session UID, and force destruction of that Session to fail. The attempt
   must return an operational failure, the encrypted cleanup state must retain
   the UID, and the row must not become `revoked`.
3. Retry through a later fresh finalizer and through account-wide credential
   revocation. Both paths must retry every retained Session; they may mark the
   row `revoked` only after provider cleanup succeeds.

Run the focused authorization lifecycle suite, the full MCP suite, TypeScript
typecheck/build, and the existing Mailcow configuration, lifecycle, nginx, and
Compose policy checks.

## Non-goals

- No Task 6 protected-resource metadata or Streamable HTTP implementation.
- No new database migration or separate cleanup-outbox table.
- No account-wide epoch rotation for client-only cleanup.
- No unrelated interaction-router refactor.
- No deployment, image publication, or cloud CLI use.
