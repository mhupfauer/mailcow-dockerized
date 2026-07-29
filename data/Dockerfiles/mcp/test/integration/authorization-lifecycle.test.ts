import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";

import type { RowDataPacket } from "mysql2/promise";
import { describe, expect, test, vi } from "vitest";

import {
  MariaDbAccountAuthorizationGate,
  MariaDbConsentAuthorizationRepository,
} from "../../src/auth/authorization-state.js";
import { MariaDbAccountAuthorizationRevoker } from "../../src/auth/authorization-revoker.js";
import type { ReauthenticationBridge } from "../../src/auth/consent-authorization-codec.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";
import {
  accountIdForMailbox,
  accountRepository,
  authPath,
  authorityMutations,
  client,
  encryptionKey,
  hidden,
  HttpClient,
  installInteractionsFixture,
  interactionState,
  issuer,
  locationPath,
  loginPage,
  loginPageFor,
  pool,
  provider,
  rawConsent,
  reachConsent,
  reachConsentFor,
  redirectUri,
  registerClient,
  resource,
  server,
  startApp,
  storedConsentScopes,
  submitLogin,
  verifierValue,
  type ConsentRow,
  type CountRow,
} from "./support/interactions-fixture.js";

describe("mailcow authorization lifecycle", () => {
  installInteractionsFixture();

  test("does not revoke active credentials when login interaction completion fails", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(callback.headers.location as string).searchParams.get(
      "code",
    );
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");

    const freshClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const freshLogin = await loginPageFor(freshClient, clientId);
    const finished = vi
      .spyOn(provider, "interactionFinished")
      .mockRejectedValueOnce(new Error("provider unavailable"));
    const response = await freshClient.postForm(freshLogin.path, {
      csrf: hidden(freshLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "replacement-app-password",
    });
    finished.mockRestore();

    expect(response.status).toBe(503);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.body).not.toContain("provider unavailable");
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId as string,
      ),
    ).toBe(true);
    expect(
      await new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      ).getActive(accountId as string, clientId),
    ).not.toBeNull();
    await expect(
      accountRepository.getCredential(accountId as string),
    ).resolves.toMatchObject({
      appPassword: "replacement-app-password",
    });
  });

  test("does not revoke active authority when pending-proof staging fails", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    const accountId = await accountIdForMailbox();
    const before = await rawConsent(accountId, clientId);

    const freshClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const freshLogin = await loginPageFor(
      freshClient,
      clientId,
      "mail.read mail.organize",
    );
    const freshLoggedIn = await freshClient.postForm(freshLogin.path, {
      csrf: hidden(freshLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "replacement-app-password",
    });
    const stage = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "stagePendingReauthentication",
      )
      .mockRejectedValueOnce(new Error("database unavailable"));
    const resume = await freshClient.get(locationPath(freshLoggedIn));
    const rejected = await freshClient.get(locationPath(resume));
    stage.mockRestore();

    expect(rejected.status).toBe(503);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    expect(rejected.body).not.toContain("database unavailable");
    expect(await rawConsent(accountId, clientId)).toBe(before);
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId,
      ),
    ).toBe(true);
    expect(
      await new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      ).getActive(accountId, clientId),
    ).not.toBeNull();
    await expect(
      accountRepository.getCredential(accountId),
    ).resolves.toMatchObject({
      appPassword: "replacement-app-password",
    });
  });

  test("fails closed when the bounded login quota map is full", async () => {
    await startApp({ maximumLoginQuotaEntries: 1 });
    interactionState.authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    const failed = await submitLogin(
      login.path,
      login.response,
      "first@example.test",
      "bad-password",
      { "x-forwarded-for": "198.51.100.1" },
    );
    expect(failed.status).toBe(401);

    const rejected = await submitLogin(
      login.path,
      login.response,
      "second@example.test",
      "bad-password",
      { "x-forwarded-for": "198.51.100.2" },
    );
    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(1);
  });

  test("fails closed when a session-bound reauthentication proof expires", async () => {
    let proofTime = 0;
    await startApp({
      reauthenticationProofTtlMs: 10,
      proofNow: () => proofTime,
    });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    expect(loggedIn.status).toBe(303);

    proofTime = 11;
    const resume = await client.get(locationPath(loggedIn));
    const consentPath = locationPath(resume);
    const rejected = await client.get(consentPath);

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
  });

  test("keeps the real-provider proof secret, session-bound, and one-time", async () => {
    const clientId = await registerClient();
    const originalFinished = provider.interactionFinished.bind(provider);
    let bridge: ReauthenticationBridge | undefined;
    const finished = vi
      .spyOn(provider, "interactionFinished")
      .mockImplementation(async (...args) => {
        const login = (
          args[2] as {
            login?: {
              reauthenticationProof?: unknown;
              authorizationEpoch?: unknown;
              reauthenticationExpiresAt?: unknown;
              reauthenticationBinding?: unknown;
            };
          }
        ).login;
        if (
          typeof login?.reauthenticationProof === "string" &&
          typeof login.authorizationEpoch === "string" &&
          Number.isSafeInteger(login.reauthenticationExpiresAt)
        ) {
          bridge = {
            proof: login.reauthenticationProof,
            authorizationEpoch: login.authorizationEpoch,
            expiresAt: login.reauthenticationExpiresAt as number,
            bindingEnvelope:
              typeof login.reauthenticationBinding === "string"
                ? login.reauthenticationBinding
                : "",
          };
        }
        return originalFinished(...args);
      });
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    expect(bridge).toBeDefined();
    finished.mockRestore();
    const resume = await client.get(locationPath(loggedIn));
    const consentPath = locationPath(resume);
    const consent = await client.get(consentPath);
    expect(consent.status).toBe(200);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const pending = await consentRepository.getStored(accountId, clientId);
    const sessionUid = pending?.pendingReauthentication?.sessionUid;
    expect(sessionUid).toBeTypeOf("string");

    const rawPending = await rawConsent(accountId, clientId);
    await expect(
      consentRepository.stagePendingReauthentication(
        accountId,
        clientId,
        resource.href,
        `${sessionUid as string}-different`,
        bridge!,
        Date.now(),
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    expect(
      (await consentRepository.getStored(accountId, clientId))
        ?.pendingReauthentication?.sessionUid,
    ).toBe(sessionUid);
    expect(bridge!.bindingEnvelope).not.toBe("");
    for (const secret of [
      bridge!.proof,
      bridge!.authorizationEpoch,
      bridge!.bindingEnvelope,
      sessionUid as string,
    ]) {
      expect(rawPending).not.toContain(secret);
      expect(client.cookieSnapshot()).not.toContain(secret);
      expect(
        [
          login.response.body,
          loggedIn.body,
          resume.body,
          consent.body,
        ].join("\n"),
      ).not.toContain(secret);
    }
    await expect(
      consentRepository.activatePending(
        accountId,
        clientId,
        resource.href,
        `${sessionUid as string}-different`,
        bridge!,
        Date.now(),
        {
          scopes: ["mail.read"],
          grantId: "wrong-session-grant",
          sessionIds: [],
        },
      ),
    ).rejects.toThrow("reauthentication proof is invalid");

    const approved = await client.postForm(consentPath, {
      csrf: hidden(consent.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    const active = await consentRepository.getActive(accountId, clientId);
    expect(active).not.toBeNull();
    await expect(
      consentRepository.activatePending(
        accountId,
        clientId,
        resource.href,
        sessionUid as string,
        bridge!,
        Date.now(),
        {
          scopes: active?.scopes ?? [],
          grantId: active?.grantId ?? "missing",
          sessionIds: active?.sessionIds ?? [],
        },
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    const rawActive = await rawConsent(accountId, clientId);
    expect(rawActive).not.toContain(bridge!.proof);
    expect(rawActive).not.toContain(bridge!.authorizationEpoch);
    expect(rawActive).not.toContain(sessionUid as string);
  });

  test("repository rejects bridge transplant and retains bounded replay and displaced-Session state", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "repository@example.test",
      "app-password",
    );
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
      {
        maximumSessions: 2,
        maximumRetiredReauthenticationBridges: 1,
      },
    );
    const clientId = "repository-client";
    const firstBridge =
      await consentRepository.issueReauthenticationBridge(
        verified.accountId,
        clientId,
        resource.href,
        {
          proof: "a".repeat(43),
          authorizationEpoch: verified.authorizationEpoch,
          expiresAt: 100,
        },
      );
    const secondBridge =
      await consentRepository.issueReauthenticationBridge(
        verified.accountId,
        clientId,
        resource.href,
        {
          proof: "b".repeat(43),
          authorizationEpoch: verified.authorizationEpoch,
          expiresAt: 100,
        },
      );
    const thirdBridge =
      await consentRepository.issueReauthenticationBridge(
        verified.accountId,
        clientId,
        resource.href,
        {
          proof: "c".repeat(43),
          authorizationEpoch: verified.authorizationEpoch,
          expiresAt: 200,
        },
      );

    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        "other-client",
        resource.href,
        "session-one",
        firstBridge,
        0,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        "https://other.example.test/mcp",
        "session-one",
        firstBridge,
        0,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");

    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "session-one",
      firstBridge,
      0,
    );
    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "session-one",
      firstBridge,
      0,
    );
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "session-transplant",
        firstBridge,
        0,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");

    const superseded = await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "session-two",
      secondBridge,
      0,
    );
    expect(superseded.sessionIds).toEqual(["session-one"]);
    expect(superseded.retiredReauthenticationBridges).toHaveLength(1);
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "session-three",
        thirdBridge,
        0,
      ),
    ).rejects.toThrow("reauthentication bridge capacity is exhausted");
    expect(
      (await consentRepository.getStored(verified.accountId, clientId))
        ?.pendingReauthentication?.sessionUid,
    ).toBe("session-two");

    const pruned = await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "session-three",
      thirdBridge,
      101,
    );
    expect(pruned.sessionIds).toEqual(["session-one", "session-two"]);
    expect(pruned.retiredReauthenticationBridges).toEqual([]);
    await consentRepository.activatePending(
      verified.accountId,
      clientId,
      resource.href,
      "session-three",
      thirdBridge,
      101,
      {
        scopes: ["mail.read"],
        grantId: "repository-grant",
        sessionIds: ["session-one", "session-two"],
      },
    );
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "session-three",
        thirdBridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await consentRepository.beginClientCleanup(
      verified.accountId,
      clientId,
      undefined,
      102,
    );
    await consentRepository.completeClientCleanup(
      verified.accountId,
      clientId,
    );
    const revoked = await consentRepository.getStored(
      verified.accountId,
      clientId,
    );
    expect(revoked).toMatchObject({
      lifecycle: "revoked",
      retiredReauthenticationBridges: [
        {
          expiresAt: 200,
        },
      ],
    });
    const revokedRaw = await rawConsent(verified.accountId, clientId);
    for (const retired of revoked?.retiredReauthenticationBridges ?? []) {
      expect(revokedRaw).not.toContain(retired.fingerprint);
    }
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "session-after-cleanup",
        thirdBridge,
        103,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
  });

  test("cleanup finalizer retention is idempotent and fails closed on rebound or capacity", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "cleanup-finalizer-repository@example.test",
      "app-password",
    );
    const clientId = "cleanup-finalizer-repository-client";
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
      { maximumSessions: 2 },
    );
    const activationBridge =
      await consentRepository.issueReauthenticationBridge(
        verified.accountId,
        clientId,
        resource.href,
        {
          proof: "d".repeat(43),
          authorizationEpoch: verified.authorizationEpoch,
          expiresAt: 200,
        },
      );
    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "existing-session",
      activationBridge,
      100,
    );
    await consentRepository.activatePending(
      verified.accountId,
      clientId,
      resource.href,
      "existing-session",
      activationBridge,
      100,
      {
        scopes: ["mail.read"],
        grantId: "cleanup-finalizer-grant",
        sessionIds: ["existing-session"],
      },
    );
    await consentRepository.beginClientCleanup(
      verified.accountId,
      clientId,
      undefined,
      101,
    );
    await consentRepository.stageClientCleanupFinalization(
      verified.accountId,
      clientId,
      new URL("/oauth/auth/cleanup-finalizer-result", issuer).href,
    );
    const bridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "e".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );

    const retained = await consentRepository.retainCleanupFinalizer(
      verified.accountId,
      clientId,
      resource.href,
      "fresh-session-one",
      bridge,
      102,
    );
    const repeated = await consentRepository.retainCleanupFinalizer(
      verified.accountId,
      clientId,
      resource.href,
      "fresh-session-one",
      bridge,
      102,
    );

    expect(repeated).toEqual(retained);
    expect(repeated.sessionIds).toEqual([
      "existing-session",
      "fresh-session-one",
    ]);
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        clientId,
        "https://other.example.test/mcp",
        "fresh-session-one",
        undefined,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        clientId,
        resource.href,
        "fresh-session-two",
        bridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        clientId,
        resource.href,
        "fresh-session-two",
        undefined,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        "wrong-client",
        resource.href,
        "fresh-session-two",
        bridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        clientId,
        "https://other.example.test/mcp",
        "fresh-session-two",
        bridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    const capacityBridge =
      await consentRepository.issueReauthenticationBridge(
        verified.accountId,
        clientId,
        resource.href,
        {
          proof: "f".repeat(43),
          authorizationEpoch: verified.authorizationEpoch,
          expiresAt: 200,
        },
      );
    await expect(
      consentRepository.retainCleanupFinalizer(
        verified.accountId,
        clientId,
        resource.href,
        "fresh-session-two",
        capacityBridge,
        102,
      ),
    ).rejects.toThrow("reauthentication session capacity is exhausted");
    expect(
      await consentRepository.getStored(verified.accountId, clientId),
    ).toEqual(retained);
    const raw = await rawConsent(verified.accountId, clientId);
    expect(raw).not.toContain("fresh-session-one");
    expect(raw).not.toContain("fresh-session-two");
    expect(raw).not.toContain(
      createHash("sha256")
        .update(capacityBridge.bindingEnvelope, "utf8")
        .digest("base64url"),
    );
    for (const retired of retained.retiredReauthenticationBridges ?? []) {
      expect(raw).not.toContain(retired.fingerprint);
    }
  });

  test("retires an unactivated bridge when client cleanup begins", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "cleanup-pending-bridge@example.test",
      "app-password",
    );
    const clientId = "cleanup-pending-bridge-client";
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const bridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "a".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        interactionUid: "cleanup-pending-bridge",
        expiresAt: 200,
      },
    );
    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "pending-session",
      bridge,
      100,
    );
    const verifiedBridgeFingerprint = (
      await consentRepository.getStored(verified.accountId, clientId)
    )?.pendingBridgeFingerprint;
    expect(verifiedBridgeFingerprint).toBeTypeOf("string");

    await consentRepository.beginClientCleanup(
      verified.accountId,
      clientId,
      "current-session",
      101,
    );
    await consentRepository.completeClientCleanup(verified.accountId, clientId);

    expect(
      await consentRepository.getStored(verified.accountId, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
      retiredReauthenticationBridges: [{ expiresAt: 200 }],
    });
    expect(await rawConsent(verified.accountId, clientId)).not.toContain(
      verifiedBridgeFingerprint as string,
    );
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "replayed-session",
        bridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
  });

  test("rejects an issued but unstaged bridge after client cleanup and accepts a fresh bridge", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "unstaged-cleanup-bridge@example.test",
      "app-password",
    );
    const clientId = "unstaged-cleanup-bridge-client";
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const initialBridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "d".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "initial-session",
      initialBridge,
      100,
    );
    await consentRepository.activatePending(
      verified.accountId,
      clientId,
      resource.href,
      "initial-session",
      initialBridge,
      100,
      {
        scopes: ["mail.read"],
        grantId: "initial-grant",
        sessionIds: ["initial-session"],
      },
    );
    const staleBridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "e".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );

    await consentRepository.beginClientCleanup(
      verified.accountId,
      clientId,
      undefined,
      101,
    );
    await consentRepository.completeClientCleanup(
      verified.accountId,
      clientId,
    );

    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "stale-session",
        staleBridge,
        102,
      ),
    ).rejects.toThrow("reauthentication proof is invalid");

    const freshBridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "f".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    await expect(
      consentRepository.stagePendingReauthentication(
        verified.accountId,
        clientId,
        resource.href,
        "fresh-session",
        freshBridge,
        102,
      ),
    ).resolves.toMatchObject({
      lifecycle: "pending_reauth",
      scopes: [],
      sessionIds: [],
    });
  });

  test("serializes bridge issuance behind an earlier same-authority mutation", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    const accountId = await accountIdForMailbox();
    const earlierMutation = await authorityMutations.acquire(
      accountId,
      clientId,
      resource.href,
    );
    expect(earlierMutation).not.toBeNull();
    const freshClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const freshLogin = await loginPageFor(freshClient, clientId);
    let observeIssue!: () => void;
    const issueEntered = new Promise<void>((resolve) => {
      observeIssue = resolve;
    });
    const originalIssue =
      MariaDbConsentAuthorizationRepository.prototype
        .issueReauthenticationBridge;
    const issue = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "issueReauthenticationBridge",
      )
      .mockImplementation(async function (...args) {
        observeIssue();
        return originalIssue.apply(this, args);
      });

    let response;
    let observedOrder;
    try {
      const submission = freshClient.postForm(freshLogin.path, {
        csrf: hidden(freshLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "replacement-app-password",
      });
      observedOrder = await Promise.race([
        issueEntered.then(() => "issued-before-release"),
        new Promise<string>((resolve) =>
          setTimeout(() => resolve("blocked-behind-mutation"), 100),
        ),
      ]);
      earlierMutation!.release();
      response = await submission;
    } finally {
      earlierMutation?.release();
      issue.mockRestore();
    }

    expect(observedOrder).toBe("blocked-behind-mutation");
    expect(response?.status).toBe(303);
  });

  test("clears revoked grant and scopes before narrow re-consent", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "narrow-reconsent@example.test",
      "app-password",
    );
    const clientId = "narrow-reconsent-client";
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const broadBridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "g".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "broad-session",
      broadBridge,
      100,
    );
    await consentRepository.activatePending(
      verified.accountId,
      clientId,
      resource.href,
      "broad-session",
      broadBridge,
      100,
      {
        scopes: ["mail.read", "mail.send"],
        grantId: "broad-grant",
        sessionIds: ["broad-session"],
      },
    );

    await consentRepository.beginClientCleanup(
      verified.accountId,
      clientId,
      undefined,
      101,
    );
    await consentRepository.completeClientCleanup(
      verified.accountId,
      clientId,
    );
    const revoked = await consentRepository.getStored(
      verified.accountId,
      clientId,
    );
    expect(revoked).toMatchObject({
      lifecycle: "revoked",
      scopes: [],
      sessionIds: [],
    });
    expect(revoked?.grantId).toBeUndefined();

    const narrowBridge = await consentRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "h".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    const pending = await consentRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "narrow-session",
      narrowBridge,
      102,
    );
    expect(pending).toMatchObject({
      lifecycle: "pending_reauth",
      scopes: [],
    });
    expect(pending.grantId).toBeUndefined();
    await consentRepository.activatePending(
      verified.accountId,
      clientId,
      resource.href,
      "narrow-session",
      narrowBridge,
      102,
      {
        scopes: ["mail.read"],
        grantId: "narrow-grant",
        sessionIds: ["narrow-session"],
      },
    );
    expect(
      await consentRepository.getActive(verified.accountId, clientId),
    ).toMatchObject({
      lifecycle: "active",
      scopes: ["mail.read"],
      grantId: "narrow-grant",
    });
  });

  test("rolls back client cleanup when retiring a pending bridge exceeds capacity", async () => {
    const verified = await accountRepository.upsertVerifiedForAuthorization(
      "cleanup-bridge-capacity@example.test",
      "app-password",
    );
    const clientId = "cleanup-bridge-capacity-client";
    const boundedRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
      { maximumRetiredReauthenticationBridges: 1 },
    );
    const firstBridge = await boundedRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "b".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    const pendingBridge = await boundedRepository.issueReauthenticationBridge(
      verified.accountId,
      clientId,
      resource.href,
      {
        proof: "c".repeat(43),
        authorizationEpoch: verified.authorizationEpoch,
        expiresAt: 200,
      },
    );
    await boundedRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "retired-session",
      firstBridge,
      100,
    );
    await boundedRepository.stagePendingReauthentication(
      verified.accountId,
      clientId,
      resource.href,
      "pending-session",
      pendingBridge,
      100,
    );

    await expect(
      boundedRepository.beginClientCleanup(
        verified.accountId,
        clientId,
        undefined,
        101,
      ),
    ).rejects.toThrow("reauthentication bridge capacity is exhausted");
    expect(
      await boundedRepository.getStored(verified.accountId, clientId),
    ).toMatchObject({
      lifecycle: "pending_reauth",
      pendingReauthentication: { sessionUid: "pending-session" },
    });
  });

  test("superseding an abandoned same-client reauthentication tracks both Sessions and rejects the old bridge", async () => {
    const clientId = await registerClient();
    const bridges: ReauthenticationBridge[] = [];
    const originalFinished = provider.interactionFinished.bind(provider);
    const finished = vi
      .spyOn(provider, "interactionFinished")
      .mockImplementation(async (...args) => {
        const login = (
          args[2] as {
            login?: {
              reauthenticationProof?: unknown;
              authorizationEpoch?: unknown;
              reauthenticationExpiresAt?: unknown;
              reauthenticationBinding?: unknown;
            };
          }
        ).login;
        if (
          typeof login?.reauthenticationProof === "string" &&
          typeof login.authorizationEpoch === "string" &&
          Number.isSafeInteger(login.reauthenticationExpiresAt)
        ) {
          bridges.push({
            proof: login.reauthenticationProof,
            authorizationEpoch: login.authorizationEpoch,
            expiresAt: login.reauthenticationExpiresAt as number,
            bindingEnvelope:
              typeof login.reauthenticationBinding === "string"
                ? login.reauthenticationBinding
                : "",
          });
        }
        return originalFinished(...args);
      });
    const port = (server.address() as AddressInfo).port;
    const firstClient = new HttpClient(port);
    const secondClient = new HttpClient(port);
    const firstLogin = await loginPageFor(firstClient, clientId);
    const firstLoggedIn = await firstClient.postForm(firstLogin.path, {
      csrf: hidden(firstLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const firstConsent = await reachConsentFor(firstClient, firstLoggedIn);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const firstPending = await consentRepository.getStored(accountId, clientId);
    const firstSessionUid =
      firstPending?.pendingReauthentication?.sessionUid;
    expect(firstSessionUid).toBeTypeOf("string");

    const secondLogin = await loginPageFor(secondClient, clientId);
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    finished.mockRestore();
    expect(bridges).toHaveLength(2);
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const superseded = await consentRepository.getStored(accountId, clientId);
    const secondSessionUid =
      superseded?.pendingReauthentication?.sessionUid;

    expect(secondSessionUid).toBeTypeOf("string");
    expect(secondSessionUid).not.toBe(firstSessionUid);
    expect(superseded?.sessionIds).toContain(firstSessionUid);
    expect(superseded?.retiredReauthenticationBridges).toHaveLength(1);
    await expect(
      consentRepository.stagePendingReauthentication(
        accountId,
        clientId,
        resource.href,
        firstSessionUid as string,
        bridges[0]!,
        Date.now(),
      ),
    ).rejects.toThrow("reauthentication proof is invalid");

    const approved = await secondClient.postForm(secondConsent.path, {
      csrf: hidden(secondConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    const callback = await secondClient.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const grantId = authorizationCode?.grantId;
    expect(grantId).toBeTypeOf("string");
    const active = await consentRepository.getActive(accountId, clientId);
    expect(active?.sessionIds).toEqual(
      expect.arrayContaining([
        firstSessionUid as string,
        secondSessionUid as string,
      ]),
    );
    expect(active?.retiredReauthenticationBridges).toHaveLength(2);
    const raw = await rawConsent(accountId, clientId);
    for (const secret of [
      bridges[0]!.proof,
      bridges[0]!.bindingEnvelope,
      bridges[1]!.proof,
      bridges[1]!.bindingEnvelope,
      firstSessionUid as string,
      secondSessionUid as string,
    ]) {
      expect(raw).not.toContain(secret);
    }

    await new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId);

    expect(await consentRepository.getStored(accountId, clientId)).toMatchObject(
      {
        lifecycle: "revoked",
        sessionIds: [],
      },
    );
    expect(
      await provider.Session.findByUid(firstSessionUid as string),
    ).toBeUndefined();
    expect(
      await provider.Session.findByUid(secondSessionUid as string),
    ).toBeUndefined();
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(code as string),
    ).toBeUndefined();
    const [authorityRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count
       FROM oidc_objects
       WHERE model IN (
         'Grant',
         'Session',
         'AccessToken',
         'RefreshToken',
         'AuthorizationCode'
       )`,
    );
    expect(authorityRows[0]?.count).toBe(0);
    await expect(
      consentRepository.stagePendingReauthentication(
        accountId,
        clientId,
        resource.href,
        "replayed-session",
        bridges[0]!,
        Date.now(),
      ),
    ).rejects.toThrow("reauthentication proof is invalid");
    expect(firstConsent.response.status).toBe(200);
  });

  test("bounds parallel current-epoch reauthentication to one row and rejects the displaced bridge", async () => {
    const clientId = await registerClient();
    const firstLogin = await loginPage(clientId);
    const firstLoggedIn = await submitLogin(firstLogin.path, firstLogin.response);
    const firstConsent = await reachConsent(firstLoggedIn);
    const secondClient = new HttpClient((server.address() as AddressInfo).port);
    const secondLogin = await loginPageFor(secondClient, clientId);
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const accountId = await accountIdForMailbox();
    const [rows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count
       FROM consents
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, clientId],
    );

    expect(rows[0]?.count).toBe(1);
    expect(JSON.parse(await rawConsent(accountId, clientId))).toMatchObject({
      version: 2,
      lifecycle: "pending_reauth",
    });
    const firstApproved = await client.postForm(firstConsent.path, {
      csrf: hidden(firstConsent.response.body, "csrf"),
      decision: "approve",
    });
    const secondApproved = await secondClient.postForm(secondConsent.path, {
      csrf: hidden(secondConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(firstApproved.status).toBe(401);
    expect(secondApproved.status).toBe(303);
    expect(secondConsent.response.status).toBe(200);
    expect(interactionState.protocolAttempts).toHaveLength(2);
    const stored = await new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    ).getActive(accountId, clientId);
    expect(stored?.lifecycle).toBe("active");
    expect(stored?.sessionIds).toHaveLength(2);
  });

  test("invalidates a pending reauthentication proof during account-wide revocation", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    expect(loggedIn.status).toBe(303);
    const [accountRows] = await pool.query<
      Array<RowDataPacket & { accountId: string }>
    >(
      `SELECT LOWER(CONCAT(
         SUBSTR(HEX(id), 1, 8), '-',
         SUBSTR(HEX(id), 9, 4), '-',
         SUBSTR(HEX(id), 13, 4), '-',
         SUBSTR(HEX(id), 17, 4), '-',
         SUBSTR(HEX(id), 21)
       )) AS accountId
       FROM accounts`,
    );
    const accountId = accountRows[0]?.accountId;
    expect(accountId).toBeTypeOf("string");
    const revoker = new MariaDbAccountAuthorizationRevoker(
      new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      ),
      provider,
      authorityMutations,
      resource.href,
    );

    await revoker.revokeCredential(accountId as string);
    const resume = await client.get(locationPath(loggedIn));
    const consentPath = locationPath(resume);
    const response = await client.get(consentPath);

    expect(response.status).toBe(401);
    expect(response.headers["cache-control"]).toContain("no-store");
  });

  test("revokes staged pending sessions and keeps unstaged bridge authority revoked", async () => {
    const stagedClientId = await registerClient();
    const unstagedClientId = await registerClient();
    const stagedClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const stagedLogin = await loginPageFor(stagedClient, stagedClientId);
    const stagedLoggedIn = await stagedClient.postForm(stagedLogin.path, {
      csrf: hidden(stagedLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const stagedResume = await stagedClient.get(
      locationPath(stagedLoggedIn),
    );
    const stagedConsent = await stagedClient.get(locationPath(stagedResume));
    expect(stagedConsent.status).toBe(200);

    const unstagedClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const unstagedLogin = await loginPageFor(
      unstagedClient,
      unstagedClientId,
    );
    const unstagedLoggedIn = await unstagedClient.postForm(
      unstagedLogin.path,
      {
        csrf: hidden(unstagedLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const pending = await consentRepository.getStored(
      accountId,
      stagedClientId,
    );
    const pendingSessionUid = pending?.pendingReauthentication?.sessionUid;
    expect(pending).toMatchObject({ lifecycle: "pending_reauth" });
    expect(pendingSessionUid).toBeTypeOf("string");
    expect(
      await consentRepository.getStored(accountId, unstagedClientId),
    ).toMatchObject({
      lifecycle: "revoked",
      scopes: [],
      sessionIds: [],
    });

    await new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId);

    expect(
      await provider.Session.findByUid(pendingSessionUid as string),
    ).toBeUndefined();
    expect(
      await consentRepository.getStored(accountId, stagedClientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
    expect(
      await consentRepository.getStored(accountId, unstagedClientId),
    ).toMatchObject({
      lifecycle: "revoked",
      scopes: [],
      sessionIds: [],
    });
    const unstagedResume = await unstagedClient.get(
      locationPath(unstagedLoggedIn),
    );
    const unstagedRejected = await unstagedClient.get(
      locationPath(unstagedResume),
    );
    expect(unstagedRejected.status).toBe(401);
    expect(unstagedRejected.headers["cache-control"]).toContain("no-store");
  });
  test("bounds consent, reuses it, expands only after prompting, and revokes it explicitly", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    expect(consent.response.body).toContain("mail.read");
    expect(consent.response.body).not.toContain("mail.send");

    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
      scopes: "mail.read mail.send administrator",
    });
    expect(approved.status).toBe(303);
    const [consents] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(consents[0]?.scopes)).toEqual(["mail.read"]);
    expect(consents[0]?.revoked).toBe(0);

    const callback = await client.get(locationPath(approved));
    const callbackUrl = new URL(callback.headers.location as string);
    expect(callbackUrl.origin).toBe(new URL(redirectUri).origin);
    const authorizationCode = await provider.AuthorizationCode.find(
      callbackUrl.searchParams.get("code") as string,
    );
    const grantId = authorizationCode?.grantId;
    expect(grantId).toBeTypeOf("string");
    const grant = await provider.Grant.find(grantId as string);
    expect(grant?.getResourceScope(resource.href)).toBe("mail.read");
    const token = await client.postForm("/oauth/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code: callbackUrl.searchParams.get("code") as string,
      code_verifier: verifierValue,
      resource: resource.href,
    });
    expect(token.status).toBe(200);
    const tokenBody = token.json() as Record<string, unknown>;
    expect(tokenBody.access_token).toBeTypeOf("string");
    expect(tokenBody.refresh_token).toBeTypeOf("string");

    const reused = await client.get(authPath(clientId, "mail.read"));
    expect(new URL(reused.headers.location as string).origin).toBe(
      new URL(redirectUri).origin,
    );

    const expansionStart = await client.get(
      authPath(clientId, "mail.read mail.send"),
    );
    const expansionPath = locationPath(expansionStart);
    expect(expansionPath).toMatch(/^\/mcp-login\//u);
    const expansion = await client.get(expansionPath);
    expect(expansion.body).toContain("mail.send");

    const expanded = await client.postForm(expansionPath, {
      csrf: hidden(expansion.body, "csrf"),
      decision: "approve",
    });
    expect(expanded.status).toBe(303);
    await client.get(locationPath(expanded));
    const [expandedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(expandedRows[0]?.scopes)).toEqual([
      "mail.read",
      "mail.send",
    ]);

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const narrowerReuse = await freshSession.get(freshConsentPath);
    expect(narrowerReuse.status).toBe(303);
    const freshCallback = await freshSession.get(locationPath(narrowerReuse));
    const freshCallbackUrl = new URL(freshCallback.headers.location as string);
    const freshCode = freshCallbackUrl.searchParams.get("code");
    expect(freshCode).toBeTypeOf("string");
    const freshAuthorizationCode = await provider.AuthorizationCode.find(
      freshCode as string,
    );
    expect(freshAuthorizationCode?.grantId).toBe(grantId);
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(1);
    const [preservedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(preservedRows[0]?.scopes)).toEqual([
      "mail.read",
      "mail.send",
    ]);
    const rawConsent = preservedRows[0]?.scopes ?? "";
    expect(rawConsent).not.toContain(grantId as string);
    const parsedConsent = JSON.parse(rawConsent) as Record<string, unknown>;
    expect(parsedConsent.authorityEnvelope).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const authorizationState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(authorizationState?.lifecycle).toBe("active");
    expect(authorizationState?.sessionIds.length).toBeGreaterThan(0);
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(rawConsent).not.toContain(sessionId);
    }

    const revocationStart = await client.get(
      authPath(clientId, "mail.read mail.send mail.organize"),
    );
    const revocationPath = locationPath(revocationStart);
    const revocation = await client.get(revocationPath);
    expect(revocation.body).toContain("mail.organize");
    const revokeForm = {
      csrf: hidden(revocation.body, "csrf"),
      decision: "revoke",
    };
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("provider unavailable"));
    const originalInteractionResult = provider.interactionResult.bind(provider);
    let stagedReturnTo: string | undefined;
    const interactionResult = vi
      .spyOn(provider, "interactionResult")
      .mockImplementation(async (...args) => {
        stagedReturnTo = await originalInteractionResult(...args);
        return stagedReturnTo;
      });
    const unavailable = await client.postForm(revocationPath, revokeForm);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    expect(unavailable.body).not.toContain("provider unavailable");
    expect(await provider.Grant.find(grantId as string)).toBeDefined();
    const [retryRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(retryRows[0]?.revoked).toBe(1);
    expect(JSON.parse(retryRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "cleanup_pending",
    });
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
    revokeAccessToken.mockRestore();

    const revoked = await client.postForm(revocationPath, revokeForm);
    expect(revoked.status).toBe(303);
    expect(revoked.headers["content-length"]).toBe("0");
    expect(revoked.headers.location).toBe(stagedReturnTo);
    interactionResult.mockRestore();
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(freshCode as string),
    ).toBeUndefined();
    expect(
      await provider.AccessToken.find(tokenBody.access_token as string),
    ).toBeUndefined();
    expect(
      await provider.RefreshToken.find(tokenBody.refresh_token as string),
    ).toBeUndefined();
    const [remainingGrants] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(remainingGrants[0]?.count).toBe(0);
    const [revokedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(revokedRows[0]?.revoked).toBe(1);
    expect(JSON.parse(revokedRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "revoked",
    });
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }

    await client.get(locationPath(revoked));
    const afterRevocation = await client.get(authPath(clientId, "mail.read"));
    const afterRevocationPath = locationPath(afterRevocation);
    expect(afterRevocationPath).toMatch(/^\/mcp-login\//u);
  });

  test("durably finalizes explicit cleanup after bookkeeping fails following current-Session destruction", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    const grantId = authorizationCode?.grantId;
    expect(accountId).toBeTypeOf("string");
    expect(grantId).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const active = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(active?.sessionIds).toHaveLength(1);

    const revocationStart = await client.get(
      authPath(clientId, "mail.read mail.send"),
    );
    const revocationPath = locationPath(revocationStart);
    const revocation = await client.get(revocationPath);
    expect(revocation.status).toBe(200);
    const revokeForm = {
      csrf: hidden(revocation.body, "csrf"),
      decision: "revoke",
    };
    const originalInteractionResult = provider.interactionResult.bind(provider);
    let stagedReturnTo: string | undefined;
    const interactionResult = vi
      .spyOn(provider, "interactionResult")
      .mockImplementation(async (...args) => {
        stagedReturnTo = await originalInteractionResult(...args);
        return stagedReturnTo;
      });
    let observedFinalizing:
      | Awaited<ReturnType<typeof consentRepository.getStored>>
      | undefined;
    let observedSessionPresence: boolean[] = [];
    const complete = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "completeClientCleanup",
      )
      .mockImplementationOnce(async (storedAccountId, storedClientId) => {
        observedFinalizing = await consentRepository.getStored(
          storedAccountId,
          storedClientId,
        );
        observedSessionPresence = await Promise.all(
          (observedFinalizing?.sessionIds ?? []).map(
            async (sessionId) =>
              (await provider.Session.findByUid(sessionId)) !== undefined,
          ),
        );
        throw new Error("database unavailable after current Session destroy");
      });

    const unavailable = await client.postForm(revocationPath, revokeForm);
    complete.mockRestore();
    interactionResult.mockRestore();

    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    expect(unavailable.headers.location).toBeUndefined();
    expect(unavailable.body).not.toContain("database unavailable");
    expect(stagedReturnTo).toBeTypeOf("string");
    expect(observedFinalizing).toMatchObject({
      lifecycle: "cleanup_finalizing",
      cleanupReturnTo: stagedReturnTo,
    });
    expect(observedSessionPresence).not.toHaveLength(0);
    expect(observedSessionPresence.every((present) => !present)).toBe(true);
    const retainedRaw = await rawConsent(accountId as string, clientId);
    expect(JSON.parse(retainedRaw)).toMatchObject({
      version: 2,
      lifecycle: "cleanup_finalizing",
    });
    expect(retainedRaw).not.toContain(stagedReturnTo as string);
    for (const sessionId of observedFinalizing?.sessionIds ?? []) {
      expect(retainedRaw).not.toContain(sessionId);
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(code as string),
    ).toBeUndefined();

    const strandedRetry = await client.postForm(revocationPath, revokeForm);
    expect(strandedRetry.status).not.toBe(303);
    expect(
      (await consentRepository.getStored(accountId as string, clientId))
        ?.lifecycle,
    ).toBe("cleanup_finalizing");

    const finalizerClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const finalizerLogin = await loginPageFor(finalizerClient, clientId);
    const finalizerLoggedIn = await finalizerClient.postForm(
      finalizerLogin.path,
      {
        csrf: hidden(finalizerLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const finalizerResume = await finalizerClient.get(
      locationPath(finalizerLoggedIn),
    );
    const finalizerPath = locationPath(finalizerResume);
    const finalized = await finalizerClient.get(finalizerPath);

    expect(finalized.status).toBe(401);
    expect(finalized.headers["cache-control"]).toContain("no-store");
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
    const [remainingAuthority] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count
       FROM oidc_objects
       WHERE model IN (
         'Grant',
         'Session',
         'AccessToken',
         'RefreshToken',
         'AuthorizationCode'
       )`,
    );
    expect(remainingAuthority[0]?.count).toBe(0);

    const reconnect = new HttpClient((server.address() as AddressInfo).port);
    const reconnectLogin = await loginPageFor(reconnect, clientId);
    const reconnectLoggedIn = await reconnect.postForm(reconnectLogin.path, {
      csrf: hidden(reconnectLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const reconnectConsent = await reachConsentFor(
      reconnect,
      reconnectLoggedIn,
    );
    const reapproved = await reconnect.postForm(reconnectConsent.path, {
      csrf: hidden(reconnectConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(reapproved.status).toBe(303);
  });

  test("retains a fresh cleanup finalizer Session before provider cleanup", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const active = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(active?.sessionIds).toHaveLength(1);
    await consentRepository.beginClientCleanup(
      accountId as string,
      clientId,
      active?.sessionIds[0],
    );
    await consentRepository.stageClientCleanupFinalization(
      accountId as string,
      clientId,
      new URL("/oauth/auth/retained-provider-result", issuer).href,
    );
    for (const sessionId of active?.sessionIds ?? []) {
      const session = await provider.Session.findByUid(sessionId);
      await session?.destroy();
    }

    const finalizerClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const finalizerLogin = await loginPageFor(finalizerClient, clientId);
    const finalizerLoggedIn = await finalizerClient.postForm(
      finalizerLogin.path,
      {
        csrf: hidden(finalizerLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const finalizerResume = await finalizerClient.get(
      locationPath(finalizerLoggedIn),
    );
    const finalizerPath = locationPath(finalizerResume);
    const originalFindSession = provider.Session.findByUid.bind(
      provider.Session,
    );
    let freshSessionUid: string | undefined;
    let freshSessionLookups = 0;
    const findSession = vi
      .spyOn(provider.Session, "findByUid")
      .mockImplementation(async (sessionUid) => {
        const session = await originalFindSession(sessionUid);
        if (session !== undefined) {
          freshSessionUid ??= sessionUid;
          if (sessionUid === freshSessionUid) {
            freshSessionLookups += 1;
            if (freshSessionLookups === 2) {
              throw new Error("session adapter unavailable");
            }
          }
        }
        return session;
      });

    const unavailable = await finalizerClient.get(finalizerPath);
    findSession.mockRestore();

    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    expect(freshSessionUid).toBeTypeOf("string");
    const retained = await consentRepository.getStored(
      accountId as string,
      clientId,
    );
    expect(retained).toMatchObject({ lifecycle: "cleanup_finalizing" });
    expect(retained?.sessionIds).toContain(freshSessionUid);
    expect(
      await provider.Session.findByUid(freshSessionUid as string),
    ).toBeDefined();
    expect(await rawConsent(accountId as string, clientId)).not.toContain(
      freshSessionUid as string,
    );

    const retryClient = new HttpClient((server.address() as AddressInfo).port);
    const retryLogin = await loginPageFor(retryClient, clientId);
    const retryLoggedIn = await retryClient.postForm(retryLogin.path, {
      csrf: hidden(retryLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const retryResume = await retryClient.get(locationPath(retryLoggedIn));
    const retried = await retryClient.get(locationPath(retryResume));

    expect(retried.status).toBe(401);
    for (const sessionId of retained?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
  });

  test("account-wide retry preserves and later destroys a retained fresh cleanup finalizer Session", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const active = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(active?.sessionIds).toHaveLength(1);
    await consentRepository.beginClientCleanup(
      accountId as string,
      clientId,
      active?.sessionIds[0],
    );
    await consentRepository.stageClientCleanupFinalization(
      accountId as string,
      clientId,
      new URL("/oauth/auth/account-cleanup-finalizer-result", issuer).href,
    );
    for (const sessionId of active?.sessionIds ?? []) {
      const session = await provider.Session.findByUid(sessionId);
      await session?.destroy();
    }

    const finalizerClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const finalizerLogin = await loginPageFor(finalizerClient, clientId);
    const finalizerLoggedIn = await finalizerClient.postForm(
      finalizerLogin.path,
      {
        csrf: hidden(finalizerLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const finalizerResume = await finalizerClient.get(
      locationPath(finalizerLoggedIn),
    );
    const finalizerPath = locationPath(finalizerResume);
    const originalFindSession = provider.Session.findByUid.bind(
      provider.Session,
    );
    let freshSessionUid: string | undefined;
    let freshSessionLookups = 0;
    const findSession = vi
      .spyOn(provider.Session, "findByUid")
      .mockImplementation(async (sessionUid) => {
        const session = await originalFindSession(sessionUid);
        if (session !== undefined) {
          freshSessionUid ??= sessionUid;
          if (sessionUid === freshSessionUid) {
            freshSessionLookups += 1;
            if (freshSessionLookups === 2) {
              throw new Error("session adapter unavailable");
            }
          }
        }
        return session;
      });
    const unavailable = await finalizerClient.get(finalizerPath);
    findSession.mockRestore();

    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    expect(freshSessionUid).toBeTypeOf("string");
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "cleanup_finalizing",
      sessionIds: expect.arrayContaining([freshSessionUid]),
    });
    const accountRevoker = new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    );
    const failAccountCleanup = vi
      .spyOn(provider.Session, "findByUid")
      .mockImplementation(async (sessionUid) => {
        if (sessionUid === freshSessionUid) {
          throw new Error("session adapter unavailable");
        }
        return originalFindSession(sessionUid);
      });

    await expect(
      accountRevoker.revokeCredential(accountId as string),
    ).rejects.toThrow("unable to revoke account authorization");
    failAccountCleanup.mockRestore();
    expect(
      await provider.Session.findByUid(freshSessionUid as string),
    ).toBeDefined();
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "cleanup_finalizing",
      sessionIds: expect.arrayContaining([freshSessionUid]),
      accountActive: false,
    });

    await expect(
      accountRevoker.revokeCredential(accountId as string),
    ).resolves.toBeUndefined();
    expect(
      await provider.Session.findByUid(freshSessionUid as string),
    ).toBeUndefined();
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
      accountActive: false,
    });
  });

  test("account-wide revocation completes a retained finalization outbox without a provider Session", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    const grantId = authorizationCode?.grantId;
    expect(accountId).toBeTypeOf("string");
    expect(grantId).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const active = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(active?.sessionIds).toHaveLength(1);
    const returnTo = new URL(
      "/oauth/auth/retained-provider-result",
      issuer,
    ).href;
    await consentRepository.beginClientCleanup(
      accountId as string,
      clientId,
      active?.sessionIds[0],
    );
    await consentRepository.stageClientCleanupFinalization(
      accountId as string,
      clientId,
      returnTo,
    );
    for (const sessionId of active?.sessionIds ?? []) {
      const session = await provider.Session.findByUid(sessionId);
      await session?.destroy();
    }
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "cleanup_finalizing",
      cleanupReturnTo: returnTo,
    });
    expect(await rawConsent(accountId as string, clientId)).not.toContain(
      returnTo,
    );

    await new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId as string);

    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId as string,
      ),
    ).toBe(false);
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(code as string),
    ).toBeUndefined();
  });

  test("serializes parallel first approvals onto one canonical grant", async () => {
    const clientId = await registerClient();
    const port = (server.address() as AddressInfo).port;
    const firstClient = new HttpClient(port);
    const secondClient = new HttpClient(port);
    const firstLogin = await loginPageFor(firstClient, clientId);
    const secondLogin = await loginPageFor(secondClient, clientId);
    const firstLoggedIn = await firstClient.postForm(firstLogin.path, {
      csrf: hidden(firstLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const firstConsent = await reachConsentFor(firstClient, firstLoggedIn);
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const originalSave = provider.Grant.prototype.save;
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return originalSave.apply(this, args);
      });

    const [firstApproved, secondApproved] = await Promise.all([
      firstClient.postForm(firstConsent.path, {
        csrf: hidden(firstConsent.response.body, "csrf"),
        decision: "approve",
      }),
      secondClient.postForm(secondConsent.path, {
        csrf: hidden(secondConsent.response.body, "csrf"),
        decision: "approve",
      }),
    ]);
    save.mockRestore();

    expect([firstApproved.status, secondApproved.status].sort()).toEqual([
      303,
      401,
    ]);
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(1);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(2);
    const successful =
      firstApproved.status === 303
        ? { client: firstClient, response: firstApproved }
        : { client: secondClient, response: secondApproved };
    const callback = await successful.client.get(
      locationPath(successful.response),
    );
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const state = await new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    ).getActive(authorizationCode?.accountId as string, clientId);
    expect(state?.sessionIds).toHaveLength(2);
    const [rawRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const raw = rawRows[0]?.scopes ?? "";
    expect(raw).not.toContain(authorizationCode?.grantId as string);
    for (const sessionId of state?.sessionIds ?? []) {
      expect(raw).not.toContain(sessionId);
    }
  });

  test("fails closed when the bounded authority mutation lock is full", async () => {
    await startApp({ maximumAuthorityMutations: 1 });
    const firstClientId = await registerClient();
    const secondClientId = await registerClient();
    const port = (server.address() as AddressInfo).port;
    const firstClient = new HttpClient(port);
    const secondClient = new HttpClient(port);
    const firstLogin = await loginPageFor(firstClient, firstClientId);
    const secondLogin = await loginPageFor(secondClient, secondClientId);
    const firstLoggedIn = await firstClient.postForm(firstLogin.path, {
      csrf: hidden(firstLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const firstConsent = await reachConsentFor(firstClient, firstLoggedIn);
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const originalSave = provider.Grant.prototype.save;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let grantSaved!: () => void;
    const saved = new Promise<void>((resolve) => {
      grantSaved = resolve;
    });
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        const grantId = await originalSave.apply(this, args);
        grantSaved();
        await waiting;
        return grantId;
      });
    const firstApproval = firstClient.postForm(firstConsent.path, {
      csrf: hidden(firstConsent.response.body, "csrf"),
      decision: "approve",
    });
    await saved;
    const rejected = await secondClient.postForm(secondConsent.path, {
      csrf: hidden(secondConsent.response.body, "csrf"),
      decision: "approve",
    });
    releaseSave();
    const approved = await firstApproval;
    save.mockRestore();

    expect(rejected.status).toBe(503);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    expect(approved.status).toBe(303);
  });

  test("preserves active authority when the mutation coordinator is saturated", async () => {
    await startApp({ maximumAuthorityMutations: 1 });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    const accountId = await accountIdForMailbox();
    const before = await rawConsent(accountId, clientId);
    const held = await authorityMutations.acquire(
      accountId,
      "saturated-authority",
      resource.href,
    );
    expect(held).not.toBeNull();

    const freshClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const freshLogin = await loginPageFor(
      freshClient,
      clientId,
      "mail.read mail.organize",
    );
    const freshLoggedIn = await freshClient.postForm(freshLogin.path, {
      csrf: hidden(freshLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "replacement-app-password",
    });
    held?.release();

    expect(freshLoggedIn.status).toBe(503);
    expect(freshLoggedIn.headers["cache-control"]).toContain("no-store");
    expect(await rawConsent(accountId, clientId)).toBe(before);
    expect(
      await new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      ).getActive(accountId, clientId),
    ).not.toBeNull();
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId,
      ),
    ).toBe(true);
    await expect(
      accountRepository.getCredential(accountId),
    ).resolves.toMatchObject({
      appPassword: "replacement-app-password",
    });
  });

  test("serializes concurrent session-cap updates without forgetting a live session", async () => {
    await startApp({ maximumConsentSessions: 2 });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(callback.headers.location as string).searchParams.get(
      "code",
    );
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId as string;

    const port = (server.address() as AddressInfo).port;
    const freshClients = [new HttpClient(port), new HttpClient(port)];
    const consentPages = await Promise.all(
      freshClients.map(async (freshClient) => {
        const freshLogin = await loginPageFor(freshClient, clientId);
        const freshLoggedIn = await freshClient.postForm(freshLogin.path, {
          csrf: hidden(freshLogin.response.body, "csrf"),
          mailbox: "user@example.test",
          app_password: "app-password",
        });
        const resume = await freshClient.get(locationPath(freshLoggedIn));
        const path = locationPath(resume);
        const response = await freshClient.get(path);
        return { freshClient, response };
      }),
    );
    expect(consentPages.map(({ response }) => response.status)).toEqual([
      303, 303,
    ]);
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const state = await consentRepository.getActive(accountId, clientId);
    expect(state?.sessionIds).toHaveLength(2);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(2);
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
  });

  test("refuses consent when the account is revoked between read and transactional save", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const originalSave = provider.Grant.prototype.save;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let grantSaved!: () => void;
    const saved = new Promise<void>((resolve) => {
      grantSaved = resolve;
    });
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        const grantId = await originalSave.apply(this, args);
        grantSaved();
        await waiting;
        return grantId;
      });
    const approval = client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await saved;
    const [accountRows] = await pool.query<
      Array<RowDataPacket & { accountId: string }>
    >(
      `SELECT LOWER(CONCAT(
         SUBSTR(HEX(id), 1, 8), '-',
         SUBSTR(HEX(id), 9, 4), '-',
         SUBSTR(HEX(id), 13, 4), '-',
         SUBSTR(HEX(id), 17, 4), '-',
         SUBSTR(HEX(id), 21)
       )) AS accountId
       FROM accounts`,
    );
    const accountId = accountRows[0]?.accountId;
    expect(accountId).toBeTypeOf("string");
    const revocation = new MariaDbAccountAuthorizationRevoker(
      new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      ),
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId as string);
    const gate = new MariaDbAccountAuthorizationGate(pool);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (!(await gate.isAccountActive(accountId as string))) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(await gate.isAccountActive(accountId as string)).toBe(false);
    releaseSave();
    const rejected = await approval;
    await revocation;
    save.mockRestore();

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(0);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(0);
    expect(
      await gate.isAccountActive(accountId as string),
    ).toBe(false);
    const oldSession = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(oldSession)).toMatch(/^\/mcp-login\//u);

    const reauthenticated = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const reauthLogin = await loginPageFor(reauthenticated, clientId);
    const reauthLoggedIn = await reauthenticated.postForm(reauthLogin.path, {
      csrf: hidden(reauthLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const reauthConsent = await reachConsentFor(
      reauthenticated,
      reauthLoggedIn,
    );
    const reapproved = await reauthenticated.postForm(reauthConsent.path, {
      csrf: hidden(reauthConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(reapproved.status).toBe(303);
  });

  test("serializes a no-row first approval with account revocation after proof validation", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    expect(
      (await consentRepository.getStored(accountId, clientId))?.lifecycle,
    ).toBe("pending_reauth");

    const originalActivation =
      MariaDbConsentAuthorizationRepository.prototype.activatePending;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let saveEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      saveEntered = resolve;
    });
    const activation = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "activatePending",
      )
      .mockImplementation(async function (...args) {
        saveEntered();
        await waiting;
        return originalActivation.apply(this, args);
      });
    const approval = client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await entered;

    const revocation = new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId);
    const gate = new MariaDbAccountAuthorizationGate(pool);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (!(await gate.isAccountActive(accountId))) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(await gate.isAccountActive(accountId)).toBe(false);
    releaseSave();
    const rejected = await approval;
    await revocation;
    activation.mockRestore();

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    expect(await consentRepository.getActive(accountId, clientId)).toBeNull();
    expect(
      await gate.isAccountActive(accountId),
    ).toBe(false);
    const [authorityRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count
       FROM oidc_objects
       WHERE model IN (
         'Grant',
         'Session',
         'AccessToken',
         'RefreshToken',
         'AuthorizationCode'
       )`,
    );
    expect(authorityRows[0]?.count).toBe(0);
  });

  test("client reauthentication cannot reactivate another client whose cleanup is pending", async () => {
    const firstClientId = await registerClient();
    const login = await loginPage(firstClientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const callbackUrl = new URL(callback.headers.location as string);
    const authorizationCode = await provider.AuthorizationCode.find(
      callbackUrl.searchParams.get("code") as string,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const token = await client.postForm("/oauth/token", {
      grant_type: "authorization_code",
      client_id: firstClientId,
      redirect_uri: redirectUri,
      code: callbackUrl.searchParams.get("code") as string,
      code_verifier: verifierValue,
      resource: resource.href,
    });
    const accessToken = (token.json() as Record<string, unknown>).access_token;
    expect(accessToken).toBeTypeOf("string");

    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("access-token adapter unavailable"));
    const findSession = vi
      .spyOn(provider.Session, "findByUid")
      .mockRejectedValueOnce(new Error("session adapter unavailable"));
    await expect(
      new MariaDbAccountAuthorizationRevoker(
        consentRepository,
        provider,
        authorityMutations,
        resource.href,
      ).revokeCredential(accountId as string),
    ).rejects.toThrow();
    revokeAccessToken.mockRestore();
    findSession.mockRestore();

    const secondClientId = await registerClient();
    const secondClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const secondLogin = await loginPageFor(secondClient, secondClientId);
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondConsent = await reachConsentFor(
      secondClient,
      secondLoggedIn,
    );
    const secondApproved = await secondClient.postForm(secondConsent.path, {
      csrf: hidden(secondConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(secondApproved.status).toBe(303);

    expect(
      await consentRepository.getActive(
        accountId as string,
        firstClientId,
      ),
    ).toBeNull();
    expect(
      await consentRepository.getActive(
        accountId as string,
        secondClientId,
      ),
    ).not.toBeNull();
    expect(accessToken).toBeTypeOf("string");
    const oldAuthorization = await client.get(
      authPath(firstClientId, "mail.read"),
    );
    const oldPrompt = await client.get(locationPath(oldAuthorization));
    expect(oldPrompt.status).not.toBe(303);
    expect(oldPrompt.headers["cache-control"]).toContain("no-store");
  });

  test("non-revoke approval cannot overwrite retained cleanup handles", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await client.get(locationPath(approved));
    const accountId = await accountIdForMailbox();

    const revocationStart = await client.get(
      authPath(clientId, "mail.read mail.organize"),
    );
    const revocationPath = locationPath(revocationStart);
    const revocation = await client.get(revocationPath);
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("token adapter unavailable"));
    const unavailable = await client.postForm(revocationPath, {
      csrf: hidden(revocation.body, "csrf"),
      decision: "revoke",
    });
    revokeAccessToken.mockRestore();
    expect(unavailable.status).toBe(503);
    const retained = await rawConsent(accountId, clientId);

    const reconnect = new HttpClient((server.address() as AddressInfo).port);
    const reconnectLogin = await loginPageFor(reconnect, clientId);
    const reconnectLoggedIn = await reconnect.postForm(reconnectLogin.path, {
      csrf: hidden(reconnectLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const cleanupPrompt = await reachConsentFor(reconnect, reconnectLoggedIn);
    const rejected = await reconnect.postForm(cleanupPrompt.path, {
      csrf: hidden(cleanupPrompt.response.body, "csrf"),
      decision: "approve",
    });

    expect(rejected.status).toBe(503);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    expect(await rawConsent(accountId, clientId)).toBe(retained);
    expect(JSON.parse(retained)).toMatchObject({
      version: 2,
      lifecycle: "cleanup_pending",
    });
  });

  test("serializes account-wide revocation behind an in-flight consent mutation without leaving authority", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(callback.headers.location as string).searchParams.get(
      "code",
    );
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");

    const expansionClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const expansionLogin = await loginPageFor(
      expansionClient,
      clientId,
      "mail.read mail.send",
    );
    const expansionLoggedIn = await expansionClient.postForm(
      expansionLogin.path,
      {
        csrf: hidden(expansionLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const expansionConsent = await reachConsentFor(
      expansionClient,
      expansionLoggedIn,
    );
    const originalSave = provider.Grant.prototype.save;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let grantSaved!: () => void;
    const saved = new Promise<void>((resolve) => {
      grantSaved = resolve;
    });
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        const grantId = await originalSave.apply(this, args);
        grantSaved();
        await waiting;
        return grantId;
      });
    const expansionApproval = expansionClient.postForm(expansionConsent.path, {
      csrf: hidden(expansionConsent.response.body, "csrf"),
      decision: "approve",
    });
    await saved;

    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const revoker = new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    );
    let revocationSettled = false;
    const revocation = revoker
      .revokeCredential(accountId as string)
      .finally(() => {
        revocationSettled = true;
      });
    const gate = new MariaDbAccountAuthorizationGate(pool);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (!(await gate.isAccountActive(accountId as string))) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(await gate.isAccountActive(accountId as string)).toBe(false);
    expect(revocationSettled).toBe(false);

    releaseSave();
    const expansionResult = await expansionApproval;
    await revocation;
    save.mockRestore();

    expect(expansionResult.status).toBe(401);
    expect(await gate.isAccountActive(accountId as string)).toBe(false);
    expect(
      await consentRepository.getActive(accountId as string, clientId),
    ).toBeNull();
    const [authorityRows] = await pool.query<
      Array<RowDataPacket & { model: string; count: number }>
    >(
      `SELECT model, COUNT(*) AS count
       FROM oidc_objects
       WHERE model IN (
         'Grant',
         'Session',
         'AccessToken',
         'RefreshToken',
         'AuthorizationCode'
       )
       GROUP BY model`,
    );
    expect(authorityRows).toEqual([]);
  });

  test("permanently quarantines legacy consent without revoking the account", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    await client.get(locationPath(approved));
    const survivingSession = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const survivingLogin = await loginPageFor(
      survivingSession,
      clientId,
      "mail.read",
    );
    const survivingLoggedIn = await survivingSession.postForm(
      survivingLogin.path,
      {
        csrf: hidden(survivingLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      },
    );
    const survivingResume = await survivingSession.get(
      locationPath(survivingLoggedIn),
    );
    const survivingConsent = await survivingSession.get(
      locationPath(survivingResume),
    );
    await survivingSession.get(locationPath(survivingConsent));
    await pool.execute(`UPDATE consents SET scopes = JSON_ARRAY('mail.read')`);

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const freshConsent = await freshSession.get(freshConsentPath);

    expect(freshConsent.status).toBe(401);
    const [quarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const quarantinedRaw = quarantinedRows[0]?.scopes ?? "";
    expect(JSON.parse(quarantinedRaw)).toMatchObject({
      version: 2,
      lifecycle: "quarantined",
    });
    expect(quarantinedRows[0]?.revoked).toBe(1);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const quarantinedState = await consentRepository.getStored(
      accountId,
      clientId,
    );
    expect(quarantinedState).toMatchObject({
      lifecycle: "quarantined",
      quarantineEvidence: '["mail.read"]',
    });
    expect(await consentRepository.getActive(accountId, clientId)).toBeNull();
    expect(await accountRepository.getCredential(accountId)).not.toBeNull();
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(accountId),
    ).toBe(true);
    const oldSessionRetry = await freshSession.get(
      authPath(clientId, "mail.read"),
    );
    expect(locationPath(oldSessionRetry)).toMatch(/^\/mcp-login\//u);

    const reauthenticated = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const reauthLogin = await loginPageFor(
      reauthenticated,
      clientId,
      "mail.read",
    );
    const reauthLoggedIn = await reauthenticated.postForm(reauthLogin.path, {
      csrf: hidden(reauthLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const oldExpansionStart = await survivingSession.get(
      authPath(clientId, "mail.read mail.organize"),
    );
    const oldExpansionPath = locationPath(oldExpansionStart);
    const oldExpansion = await survivingSession.get(oldExpansionPath);
    expect(oldExpansion.status).toBe(401);
    const reauthResume = await reauthenticated.get(
      locationPath(reauthLoggedIn),
    );
    const reauthRejected = await reauthenticated.get(
      locationPath(reauthResume),
    );
    expect(reauthRejected.status).toBe(401);
    const [stillQuarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(stillQuarantinedRows[0]?.revoked).toBe(1);
    expect(JSON.parse(stillQuarantinedRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "quarantined",
    });
    expect(
      (await consentRepository.getStored(accountId, clientId))
        ?.quarantineEvidence,
    ).toBe('["mail.read"]');
  });

  test("quarantines plaintext scope elevation that is not authenticated by the authority envelope", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    await client.get(locationPath(approved));
    const accountId = await accountIdForMailbox();
    await pool.execute(
      `UPDATE consents
       SET scopes = JSON_SET(
         scopes,
         '$.scopes',
         JSON_ARRAY('mail.read', 'mail.send')
       )
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, clientId],
    );
    const tamperedRaw = await rawConsent(accountId, clientId);

    const expansion = await client.get(authPath(clientId, "mail.send"));
    const rejected = await client.get(locationPath(expansion));

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    expect(await consentRepository.getStored(accountId, clientId)).toMatchObject(
      {
        lifecycle: "quarantined",
        quarantineEvidence: tamperedRaw,
      },
    );
    expect(await consentRepository.getActive(accountId, clientId)).toBeNull();
  });

  test("quarantines tampered authority with encrypted recovery evidence", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    await client.get(locationPath(approved));
    await pool.execute(
      `UPDATE consents
       SET scopes = JSON_SET(scopes, '$.authorityEnvelope', 'tampered')`,
    );
    const [tamperedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const tamperedRaw = tamperedRows[0]?.scopes;

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const freshConsent = await freshSession.get(freshConsentPath);

    expect(freshConsent.status).toBe(401);
    expect(freshConsent.body).not.toContain("tampered");
    const [quarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(quarantinedRows[0]?.scopes).not.toBe(tamperedRaw);
    expect(JSON.parse(quarantinedRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "quarantined",
    });
    expect(quarantinedRows[0]?.scopes).not.toContain("tampered");
    expect(quarantinedRows[0]?.revoked).toBe(1);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    expect(
      (await consentRepository.getStored(accountId, clientId))
        ?.quarantineEvidence,
    ).toBe(tamperedRaw);
  });

  test("quarantines a structurally malformed row with encrypted recovery evidence", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await client.get(locationPath(approved));
    await pool.execute(
      `UPDATE consents
       SET scopes = JSON_OBJECT('unexpected', JSON_ARRAY('mail.read'))`,
    );
    const [malformedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const malformedRaw = malformedRows[0]?.scopes;

    const oldSession = new HttpClient((server.address() as AddressInfo).port);
    const oldLogin = await loginPageFor(oldSession, clientId);
    const oldLoggedIn = await oldSession.postForm(oldLogin.path, {
      csrf: hidden(oldLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const oldResume = await oldSession.get(locationPath(oldLoggedIn));
    const oldConsentPath = locationPath(oldResume);
    const rejected = await oldSession.get(oldConsentPath);

    expect(rejected.status).toBe(401);
    const [quarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(quarantinedRows[0]?.scopes).not.toBe(malformedRaw);
    expect(JSON.parse(quarantinedRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "quarantined",
    });
    expect(quarantinedRows[0]?.revoked).toBe(1);
    const accountId = await accountIdForMailbox();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    expect(
      (await consentRepository.getStored(accountId, clientId))
        ?.quarantineEvidence,
    ).toBe(malformedRaw);
  });

  test("quarantines an already-revoked malformed row instead of reporting revoke success", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await client.get(locationPath(approved));
    const accountId = await accountIdForMailbox();

    const expansionStart = await client.get(
      authPath(clientId, "mail.read mail.organize"),
    );
    const expansionPath = locationPath(expansionStart);
    const expansion = await client.get(expansionPath);
    const malformed = JSON.stringify({ unexpected: ["mail.read"] });
    await pool.execute(
      `UPDATE consents
       SET scopes = JSON_OBJECT('unexpected', JSON_ARRAY('mail.read')),
           revoked_at = UTC_TIMESTAMP(6)
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, clientId],
    );

    const rejected = await client.postForm(expansionPath, {
      csrf: hidden(expansion.body, "csrf"),
      decision: "revoke",
    });

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    const quarantined = JSON.parse(await rawConsent(accountId, clientId)) as {
      version?: number;
      lifecycle?: string;
      authorityEnvelope?: string;
    };
    expect(quarantined).toMatchObject({
      version: 2,
      lifecycle: "quarantined",
    });
    expect(quarantined.authorityEnvelope).toMatch(/^v1\./u);
    expect(JSON.stringify(quarantined)).not.toContain(malformed);
  });

  test("retries explicit cleanup from a revoked encrypted association before quarantine", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await client.get(locationPath(approved));
    const accountId = await accountIdForMailbox();
    const revocationStart = await client.get(
      authPath(clientId, "mail.read mail.organize"),
    );
    const revocationPath = locationPath(revocationStart);
    const revocation = await client.get(revocationPath);
    const revokeForm = {
      csrf: hidden(revocation.body, "csrf"),
      decision: "revoke",
    };
    const originalFindSession = provider.Session.findByUid.bind(
      provider.Session,
    );
    let sessionFinds = 0;
    const findSession = vi
      .spyOn(provider.Session, "findByUid")
      .mockImplementation(async (sessionUid) => {
        sessionFinds += 1;
        if (sessionFinds === 3) {
          throw new Error("session adapter unavailable");
        }
        return originalFindSession(sessionUid);
      });

    const unavailable = await client.postForm(revocationPath, revokeForm);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    const [retryRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(retryRows[0]?.revoked).toBe(1);
    const retryRaw = retryRows[0]?.scopes;
    expect(JSON.parse(retryRaw ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "cleanup_finalizing",
    });

    const retried = await client.postForm(revocationPath, revokeForm);
    findSession.mockRestore();
    expect(retried.status).toBe(303);
    expect(retried.headers["content-length"]).toBe("0");
    const [completedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(completedRows[0]?.scopes).not.toBe(retryRaw);
    expect(JSON.parse(completedRows[0]?.scopes ?? "{}")).toMatchObject({
      version: 2,
      lifecycle: "revoked",
    });
    expect(completedRows[0]?.revoked).toBe(1);
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    expect(await consentRepository.getStored(accountId, clientId)).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
    expect(
      (await consentRepository.getStored(accountId, clientId))?.grantId,
    ).toBeUndefined();
  });

  test("bounds remembered consent sessions and destroys the evicted provider session", async () => {
    await startApp({ maximumConsentSessions: 2 });
    const clientId = await registerClient();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const firstCode = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const firstAuthorizationCode = await provider.AuthorizationCode.find(
      firstCode as string,
    );
    const accountId = firstAuthorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const firstState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    const firstSessionId = firstState?.sessionIds[0];
    expect(firstSessionId).toBeTypeOf("string");

    for (let index = 0; index < 2; index += 1) {
      const freshSession = new HttpClient(
        (server.address() as AddressInfo).port,
      );
      const freshLogin = await loginPageFor(
        freshSession,
        clientId,
        "mail.read",
      );
      const freshLoggedIn = await freshSession.postForm(freshLogin.path, {
        csrf: hidden(freshLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      });
      const freshResume = await freshSession.get(locationPath(freshLoggedIn));
      const freshConsentPath = locationPath(freshResume);
      const reused = await freshSession.get(freshConsentPath);
      expect(reused.status).toBe(303);
      await freshSession.get(locationPath(reused));
    }

    const boundedState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(boundedState?.sessionIds).toHaveLength(2);
    expect(boundedState?.sessionIds).not.toContain(firstSessionId);
    expect(
      await provider.Session.findByUid(firstSessionId as string),
    ).toBeUndefined();
    for (const sessionId of boundedState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
  });

  test("revokes account credentials, consent, grants, tokens, codes, and sessions together", async () => {
    const clientId = await registerClient();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const callbackUrl = new URL(callback.headers.location as string);
    const code = callbackUrl.searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    const grantId = authorizationCode?.grantId;
    expect(accountId).toBeTypeOf("string");
    expect(grantId).toBeTypeOf("string");
    const token = await client.postForm("/oauth/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code: code as string,
      code_verifier: verifierValue,
      resource: resource.href,
    });
    expect(token.status).toBe(200);
    const tokenBody = token.json() as Record<string, unknown>;

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshLogin = await loginPageFor(freshSession, clientId, "mail.read");
    const freshLoggedIn = await freshSession.postForm(freshLogin.path, {
      csrf: hidden(freshLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const reused = await freshSession.get(freshConsentPath);
    const freshCallback = await freshSession.get(locationPath(reused));
    const freshCode = new URL(
      freshCallback.headers.location as string,
    ).searchParams.get("code");
    const state = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(state?.sessionIds).toHaveLength(2);

    const revoker = new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    );
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("provider unavailable"));
    await expect(
      revoker.revokeCredential(accountId as string),
    ).rejects.toThrow();
    const authorizationGate = new MariaDbAccountAuthorizationGate(pool);
    expect(await authorizationGate.isAccountActive(accountId as string)).toBe(
      false,
    );
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    const survivingSession = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(survivingSession)).toMatch(/^\/mcp-login\//u);
    revokeAccessToken.mockRestore();
    await revoker.revokeCredential(accountId as string);

    expect(
      await accountRepository.getCredential(accountId as string),
    ).toBeNull();
    expect(
      await consentRepository.getActive(accountId as string, clientId),
    ).toBeNull();
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(freshCode as string),
    ).toBeUndefined();
    expect(
      await provider.AccessToken.find(tokenBody.access_token as string),
    ).toBeUndefined();
    expect(
      await provider.RefreshToken.find(tokenBody.refresh_token as string),
    ).toBeUndefined();
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    const completed = await rawConsent(accountId as string, clientId);
    expect(JSON.parse(completed)).toMatchObject({
      version: 2,
      lifecycle: "revoked",
    });
    const grantFind = vi.spyOn(provider.Grant, "find");
    const sessionFind = vi.spyOn(provider.Session, "findByUid");
    await revoker.revokeCredential(accountId as string);
    grantFind.mockRestore();
    sessionFind.mockRestore();
    expect(await rawConsent(accountId as string, clientId)).toBe(completed);
    expect(grantFind).not.toHaveBeenCalled();
    expect(sessionFind).not.toHaveBeenCalled();
    const afterRevocation = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(afterRevocation)).toMatch(/^\/mcp-login\//u);
  });

  test("fails closed and cleans authority when the credential envelope is corrupted", async () => {
    const clientId = await registerClient();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    const grantId = authorizationCode?.grantId;
    expect(accountId).toBeTypeOf("string");
    expect(grantId).toBeTypeOf("string");
    const state = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(state?.sessionIds).not.toHaveLength(0);
    await pool.execute(
      `UPDATE accounts
       SET credential_envelope = 'tampered'
       WHERE id = UNHEX(REPLACE(?, '-', ''))`,
      [accountId],
    );

    await new MariaDbAccountAuthorizationRevoker(
      consentRepository,
      provider,
      authorityMutations,
      resource.href,
    ).revokeCredential(accountId as string);

    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId as string,
      ),
    ).toBe(false);
    expect(
      await consentRepository.getStored(accountId as string, clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      sessionIds: [],
    });
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
  });
});
