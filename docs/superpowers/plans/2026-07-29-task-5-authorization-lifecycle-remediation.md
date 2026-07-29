# Task 5 Authorization Lifecycle Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make client authorization cleanup consume every pending bridge and
durably retain every fresh cleanup-finalizer Session before provider mutation.

**Architecture:** Continue using the authenticated authorization authority
inside the existing `consents.scopes` envelope. First make entry into cleanup
atomically convert pending bridge and Session state into cleanup evidence.
Then add one transactional repository operation that joins a fresh finalizer
Session and bridge to an existing cleanup outbox before strict provider
cleanup.

**Tech Stack:** TypeScript 7, Node.js 24, oidc-provider 9.10, mysql2,
Vitest/Testcontainers, MariaDB 10.11.

## Global Constraints

- Follow
  `docs/superpowers/specs/2026-07-29-task-5-authorization-lifecycle-remediation-design.md`.
- Do not add or edit a database migration.
- Do not rotate the account-wide authorization epoch for client-only cleanup.
- Preserve account → consent database lock ordering and the existing
  account/client/resource mutation coordinator.
- Never evict a live Session UID or retired bridge fingerprint; capacity
  exhaustion fails before provider mutation.
- Provider cleanup failure leaves `cleanup_pending` or
  `cleanup_finalizing`; only complete provider cleanup may produce `revoked`.
- Keep Session IDs, fingerprints, cleanup return locations, mailbox
  addresses, app passwords, grants, and tokens out of plaintext persistence
  and responses.
- Do not implement Task 6, refactor unrelated interaction code, deploy,
  publish images, or use cloud CLIs.

---

### Task 1: Retire pending bridges when client cleanup begins

**Files:**
- Modify:
  `data/Dockerfiles/mcp/src/auth/authorization-state.ts`
- Test:
  `data/Dockerfiles/mcp/test/integration/authorization-lifecycle.test.ts`

**Interfaces:**
- Consumes: `liveRetiredBridges`, `retireBridge`,
  `pendingBridgeFingerprint`, and
  `pendingReauthentication.{sessionUid,expiresAt}`.
- Produces:

```ts
beginClientCleanup(
  accountId: string,
  clientId: string,
  currentSessionUid?: string,
  now?: number,
): Promise<ConsentAuthorizationState | null>
```

- [ ] **Step 1: Add a failing unactivated-bridge cleanup regression**

Add a repository-level integration test beside the existing retired-bridge
coverage. Issue and stage a bridge without calling `activatePending`, then
begin and complete client cleanup:

```ts
const bridge = await consentRepository.issueReauthenticationBridge(
  accountId,
  clientId,
  resource.href,
  {
    authorizationEpoch,
    interactionUid: "cleanup-pending-bridge",
    expiresAt: 200,
  },
);
await consentRepository.stagePendingReauthentication(
  accountId,
  clientId,
  resource.href,
  "pending-session",
  bridge,
  100,
);
await consentRepository.beginClientCleanup(
  accountId,
  clientId,
  "current-session",
  101,
);
await consentRepository.completeClientCleanup(accountId, clientId);

await expect(
  consentRepository.stagePendingReauthentication(
    accountId,
    clientId,
    resource.href,
    "replayed-session",
    bridge,
    102,
  ),
).rejects.toThrow("reauthentication proof is invalid");
```

Assert before the replay that:

```ts
expect(await consentRepository.getStored(accountId, clientId)).toMatchObject({
  lifecycle: "revoked",
  sessionIds: [],
  retiredReauthenticationBridges: [{ expiresAt: 200 }],
});
expect(await rawConsent(accountId, clientId)).not.toContain(
  verifiedBridgeFingerprint,
);
```

Obtain `verifiedBridgeFingerprint` only through the stored parsed state before
completion; never decrypt or duplicate production codec logic in the test.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cd data/Dockerfiles/mcp
DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npx vitest run test/integration/authorization-lifecycle.test.ts \
  -t "retires an unactivated bridge when client cleanup begins"
```

Expected: FAIL because the bridge is absent from
`retiredReauthenticationBridges` and restaging succeeds.

- [ ] **Step 3: Implement atomic bridge retirement**

In `beginClientCleanup`, default `now` to `Date.now()`. While holding the
existing account and consent row locks:

```ts
let retiredReauthenticationBridges =
  this.liveRetiredBridges(existing, now);

if (
  existing.lifecycle === "pending_reauth" &&
  existing.pendingBridgeFingerprint !== undefined &&
  existing.pendingReauthentication !== undefined
) {
  retiredReauthenticationBridges = this.retireBridge(
    retiredReauthenticationBridges,
    existing.pendingBridgeFingerprint,
    existing.pendingReauthentication.expiresAt,
    now,
  );
}

const sessionIds = [
  ...new Set([
    ...existing.sessionIds,
    ...(existing.pendingReauthentication === undefined
      ? []
      : [existing.pendingReauthentication.sessionUid]),
    ...(currentSessionUid === undefined ? [] : [currentSessionUid]),
  ]),
];
if (sessionIds.length > this.maximumSessions) {
  throw new ReauthenticationBridgeCapacityError(
    "reauthentication session capacity is exhausted",
  );
}
```

Write `cleanup_pending` with `sessionIds`,
`retiredReauthenticationBridges`, and no pending authority fields. Any
capacity error must roll back the whole transaction.

- [ ] **Step 4: Add and run the capacity rollback regression**

Construct a repository with
`maximumRetiredReauthenticationBridges: 1`, fill its single live retired
marker, stage another live pending bridge, and call `beginClientCleanup`.
Require the capacity error and unchanged `pending_reauth` state:

```ts
await expect(
  boundedRepository.beginClientCleanup(accountId, clientId, undefined, 101),
).rejects.toThrow("reauthentication bridge capacity is exhausted");
expect(await boundedRepository.getStored(accountId, clientId)).toMatchObject({
  lifecycle: "pending_reauth",
  pendingReauthentication: { sessionUid: "pending-session" },
});
```

Run:

```bash
DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npx vitest run test/integration/authorization-lifecycle.test.ts \
  -t "client cleanup"
```

Expected: PASS.

- [ ] **Step 5: Run Task 1 regression and static gates**

Run:

```bash
DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npx vitest run test/integration/authorization-lifecycle.test.ts
npm run typecheck
git diff --check
```

Expected: lifecycle suite and typecheck PASS; no whitespace errors.

- [ ] **Step 6: Commit**

```bash
git add \
  data/Dockerfiles/mcp/src/auth/authorization-state.ts \
  data/Dockerfiles/mcp/test/integration/authorization-lifecycle.test.ts
git commit -m "fix: consume pending bridges during client cleanup"
```

---

### Task 2: Persist fresh cleanup-finalizer Sessions before provider cleanup

**Files:**
- Modify:
  `data/Dockerfiles/mcp/src/auth/authorization-state.ts`
- Modify:
  `data/Dockerfiles/mcp/src/auth/interactions.ts`
- Test:
  `data/Dockerfiles/mcp/test/integration/authorization-lifecycle.test.ts`

**Interfaces:**
- Consumes: `verifiedBridge`, `liveRetiredBridges`, `retireBridge`,
  `lockAccountRow`, `lockConsent`, and the existing strict
  `revokeProviderAuthorityBestEffort`.
- Produces:

```ts
retainCleanupFinalizer(
  accountId: string,
  clientId: string,
  resource: string,
  currentSessionUid: string,
  bridge: ReauthenticationBridge | undefined,
  now: number,
): Promise<ConsentAuthorizationState>
```

- [ ] **Step 1: Add a failing fresh-finalizer durability regression**

Extend the real-provider cleanup-finalization coverage. Create an active
authorization, enter `cleanup_finalizing`, then authenticate through a fresh
HTTP client. On the fresh finalizer request, force the provider lookup or
destroy for that newly created Session to reject once.

Assert the request returns `503` with `Cache-Control: no-store`, then inspect
the repository:

```ts
const retained = await consentRepository.getStored(accountId, clientId);
expect(retained).toMatchObject({ lifecycle: "cleanup_finalizing" });
expect(retained?.sessionIds).toContain(freshSessionUid);
expect(await provider.Session.findByUid(freshSessionUid)).toBeDefined();
expect(await rawConsent(accountId, clientId)).not.toContain(freshSessionUid);
```

Restore the provider operation, retry cleanup through another fresh browser,
and require every retained Session to be destroyed before the row becomes:

```ts
expect(await consentRepository.getStored(accountId, clientId)).toMatchObject({
  lifecycle: "revoked",
  sessionIds: [],
});
```

- [ ] **Step 2: Run the fresh-finalizer test and verify RED**

Run:

```bash
DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npx vitest run test/integration/authorization-lifecycle.test.ts \
  -t "retains a fresh cleanup finalizer Session before provider cleanup"
```

Expected: FAIL because the fresh Session UID is missing from stored cleanup
state after the forced provider failure.

- [ ] **Step 3: Implement `retainCleanupFinalizer` transactionally**

Verify a presented bridge using the existing codec before opening the
transaction. Then lock the account and consent rows. Require a non-quarantined
`cleanup_pending` or `cleanup_finalizing` state.

Use this idempotency rule:

```ts
const alreadyRetired =
  verified !== undefined &&
  retiredReauthenticationBridges.some(
    (entry) => entry.fingerprint === verified.fingerprint,
  );
const alreadyRetained = existing.sessionIds.includes(currentSessionUid);

if (alreadyRetired && !alreadyRetained) {
  throw new InvalidReauthenticationProofError();
}
if (!alreadyRetained && verified === undefined) {
  throw new InvalidReauthenticationProofError();
}
```

For a new bridge, require its epoch to equal the locked account epoch and its
expiry to be greater than `now`, then retire it. Add the current Session UID
without eviction and fail with
`"reauthentication session capacity is exhausted"` if the set would exceed
`maximumSessions`.

Persist the same cleanup lifecycle, grant, return location, scopes, and
account-active value with the updated encrypted Session and retired-bridge
sets. Return the stored state. A repeated call with the same Session and
bridge returns the same logical state.

- [ ] **Step 4: Add repository idempotency, rebound, and capacity coverage**

Put a consent into `cleanup_finalizing`, issue a bridge, and retain
`"fresh-session-one"`. Require that the exact repeated call succeeds without
duplicating state. Then require the same bridge with
`"fresh-session-two"` and a new Session without a bridge to fail:

```ts
await expect(
  consentRepository.retainCleanupFinalizer(
    accountId,
    clientId,
    resource.href,
    "fresh-session-two",
    bridge,
    102,
  ),
).rejects.toThrow("reauthentication proof is invalid");

await expect(
  consentRepository.retainCleanupFinalizer(
    accountId,
    clientId,
    resource.href,
    "fresh-session-two",
    undefined,
    102,
  ),
).rejects.toThrow("reauthentication proof is invalid");
```

Use a repository at its `maximumSessions` limit and require that joining a
new Session fails without changing the stored cleanup state. Pass a wrong
client and wrong resource to separately require proof rejection. Assert the
raw row contains neither Session UID nor bridge fingerprint.

- [ ] **Step 5: Join fresh finalizers before provider mutation**

Change `finalizeStrandedCleanup` to accept the current bridge and timestamp.
Its first state mutation must be:

```ts
const retained = await consentRepository.retainCleanupFinalizer(
  accountId,
  clientId,
  dependencies.resource.href,
  currentSessionId,
  bridge,
  now,
);
```

Pass `retained.grantId` and `retained.sessionIds` to strict provider cleanup,
then call `completeClientCleanup`. Update both GET and POST interaction paths
to pass `bridge` and `now()`. Do not catch and suppress provider failures.

- [ ] **Step 6: Add account-wide retry coverage**

Repeat the forced fresh-Session cleanup failure, then call the existing
account-wide credential revoker instead of a browser retry. Require:

```ts
await expect(accountRevoker.revokeCredential(accountId)).resolves.toBeUndefined();
expect(await provider.Session.findByUid(freshSessionUid)).toBeUndefined();
expect(await consentRepository.getStored(accountId, clientId)).toMatchObject({
  lifecycle: "revoked",
  sessionIds: [],
  accountActive: false,
});
```

Also assert that a provider cleanup rejection makes
`revokeCredential(accountId)` reject and leaves the retained Session and
cleanup lifecycle intact.

- [ ] **Step 7: Run focused and full MCP verification**

Run:

```bash
DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npx vitest run test/integration/authorization-lifecycle.test.ts

DOCKER_HOST=unix:///Users/markushupfauer/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
npm test

npm run typecheck
npm run build
```

Expected: 13 MCP test files PASS, with all authorization lifecycle
regressions green; typecheck and build PASS.

- [ ] **Step 8: Run Mailcow integration gates**

From the repository root:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
python3 -m unittest data/Dockerfiles/nginx/test_bootstrap.py
COMPOSE_PROFILES=mcp docker compose config -q
git diff --check
```

Expected: all helper and nginx tests PASS, rendered Compose validates, and
there are no whitespace errors.

- [ ] **Step 9: Commit**

```bash
git add \
  data/Dockerfiles/mcp/src/auth/authorization-state.ts \
  data/Dockerfiles/mcp/src/auth/interactions.ts \
  data/Dockerfiles/mcp/test/integration/authorization-lifecycle.test.ts
git commit -m "fix: retain cleanup finalizer sessions"
```

Review the complete remediation against both findings before beginning Task 6.
