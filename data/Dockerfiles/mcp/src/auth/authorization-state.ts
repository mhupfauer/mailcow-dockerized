import { createHash, randomBytes } from "node:crypto";

import type {
  Pool,
  PoolConnection,
  RowDataPacket,
} from "mysql2/promise";

import { MariaDbAccountRepository } from "./account-repository.js";
import {
  ConsentAuthorizationCodec,
  validAccountId,
  type ConsentAuthorizationState,
  type ConsentSealOptions,
  type PendingReauthenticationAuthority,
  type ReauthenticationBridge,
  type ReauthenticationBridgeClaims,
  type RetiredReauthenticationBridge,
  type VerifiedReauthenticationBridge,
} from "./consent-authorization-codec.js";
import type { CredentialVault } from "./crypto-vault.js";

const defaultMaximumSessions = 32;
const defaultMaximumRetiredReauthenticationBridges = 128;

function compareRetiredBridges(
  first: RetiredReauthenticationBridge,
  second: RetiredReauthenticationBridge,
): number {
  const expiryOrder = first.expiresAt - second.expiresAt;
  if (expiryOrder !== 0) {
    return expiryOrder;
  }
  return first.fingerprint < second.fingerprint
    ? -1
    : first.fingerprint > second.fingerprint
      ? 1
      : 0;
}

interface ConsentRow extends RowDataPacket {
  clientId: string;
  value: string;
  accountActive: number;
}

interface AccountLockRow extends RowDataPacket {
  present: number;
}

export class InactiveAuthorizationAccountError extends Error {
  constructor() {
    super("authorization account is inactive");
  }
}

export class InvalidReauthenticationProofError extends Error {
  constructor() {
    super("reauthentication proof is invalid");
  }
}

export class CleanupPendingAuthorizationError extends Error {
  constructor() {
    super("authorization cleanup is pending");
  }
}

export class ReauthenticationBridgeCapacityError extends Error {
  constructor(message = "reauthentication bridge capacity is exhausted") {
    super(message);
  }
}

export interface ConsentAuthorizationRepositoryOptions {
  maximumSessions?: number;
  maximumRetiredReauthenticationBridges?: number;
}

export interface AccountAuthorizationGate {
  isAccountActive(accountId: string): Promise<boolean>;
}

export interface AuthorizationMutationLease {
  release(): void;
}

export interface AuthorizationMutationCoordinator {
  acquire(
    accountId: string,
    clientId: string,
    resource: string,
  ): Promise<AuthorizationMutationLease | null>;
}

export class BoundedAuthorizationMutationCoordinator implements AuthorizationMutationCoordinator {
  private readonly tails = new Map<string, Promise<void>>();
  private pending = 0;

  constructor(private readonly maximum: number) {
    if (!Number.isSafeInteger(maximum) || maximum < 1) {
      throw new Error("invalid authorization mutation limit");
    }
  }

  async acquire(
    accountId: string,
    clientId: string,
    resource: string,
  ): Promise<AuthorizationMutationLease | null> {
    if (this.pending >= this.maximum) {
      return null;
    }
    this.pending += 1;
    const key = createHash("sha256")
      .update(`${accountId}\u0000${clientId}\u0000${resource}`, "utf8")
      .digest("base64url");
    const predecessor = this.tails.get(key) ?? Promise.resolve();
    let releaseNext!: () => void;
    const current = new Promise<void>((resolve) => {
      releaseNext = resolve;
    });
    this.tails.set(key, current);
    await predecessor;
    let released = false;
    return {
      release: () => {
        if (released) {
          return;
        }
        released = true;
        this.pending -= 1;
        if (this.tails.get(key) === current) {
          this.tails.delete(key);
        }
        releaseNext();
      },
    };
  }
}

export class MariaDbConsentAuthorizationRepository {
  private readonly accountRepository: MariaDbAccountRepository;
  private readonly codec: ConsentAuthorizationCodec;
  private readonly maximumSessions: number;
  private readonly maximumRetiredReauthenticationBridges: number;

  constructor(
    private readonly pool: Pool,
    vault: CredentialVault,
    expectedResource: string,
    {
      maximumSessions = defaultMaximumSessions,
      maximumRetiredReauthenticationBridges =
        defaultMaximumRetiredReauthenticationBridges,
    }: ConsentAuthorizationRepositoryOptions = {},
  ) {
    if (
      !Number.isSafeInteger(maximumSessions) ||
      maximumSessions < 1 ||
      !Number.isSafeInteger(maximumRetiredReauthenticationBridges) ||
      maximumRetiredReauthenticationBridges < 1 ||
      maximumRetiredReauthenticationBridges > 1_024
    ) {
      throw new Error("invalid consent authorization limits");
    }
    this.accountRepository = new MariaDbAccountRepository(pool, vault);
    this.codec = new ConsentAuthorizationCodec(vault, expectedResource);
    this.maximumSessions = maximumSessions;
    this.maximumRetiredReauthenticationBridges =
      maximumRetiredReauthenticationBridges;
  }

  async issueReauthenticationBridge(
    accountId: string,
    clientId: string,
    resource: string,
    claims: ReauthenticationBridgeClaims,
  ): Promise<ReauthenticationBridge> {
    if (!validAccountId(accountId) || clientId === "" || resource === "") {
      throw new InvalidReauthenticationProofError();
    }
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const account =
        await this.accountRepository.getAuthorizationEpochLocked(
          connection,
          accountId,
        );
      if (
        account === null ||
        account.authorizationEpoch !== claims.authorizationEpoch
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const newAuthorizationGeneration =
        randomBytes(32).toString("base64url");
      await this.insertStateIfAbsent(
        connection,
        accountId,
        {
          lifecycle: "revoked",
          clientId,
          resource,
          scopes: [],
          authorizationGeneration: newAuthorizationGeneration,
          sessionIds: [],
          accountActive: !account.revoked,
          retiredReauthenticationBridges: [],
        },
      );
      let existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
      if (existing === null) {
        throw new InvalidReauthenticationProofError();
      }
      let authorizationGeneration = existing?.authorizationGeneration;
      if (authorizationGeneration === undefined) {
        authorizationGeneration = newAuthorizationGeneration;
        if (existing?.lifecycle === "revoked") {
          existing = {
            ...existing,
            scopes: [],
            grantId: undefined,
            sessionIds: [],
            authorizationGeneration,
          };
        } else {
          existing =
            existing === null
              ? {
                  lifecycle: "revoked",
                  clientId,
                  resource,
                  scopes: [],
                  authorizationGeneration,
                  sessionIds: [],
                  accountActive: !account.revoked,
                  retiredReauthenticationBridges: [],
                }
              : { ...existing, authorizationGeneration };
        }
        const pending =
          existing.lifecycle === "pending_reauth" &&
          existing.pendingBridgeFingerprint !== undefined &&
          existing.pendingAuthorizationEpoch !== undefined &&
          existing.pendingReauthentication !== undefined
            ? {
                bridgeFingerprint: existing.pendingBridgeFingerprint,
                authorizationEpoch: existing.pendingAuthorizationEpoch,
                sessionUid: existing.pendingReauthentication.sessionUid,
                expiresAt: existing.pendingReauthentication.expiresAt,
              }
            : undefined;
        await this.writeStateLocked(connection, accountId, existing, {
          ...(pending === undefined ? {} : { pending }),
          ...(existing.consumedProofDigest === undefined
            ? {}
            : { consumedProofDigest: existing.consumedProofDigest }),
          ...(existing.quarantineEvidence === undefined
            ? {}
            : { evidence: existing.quarantineEvidence }),
        });
      }
      const bridge = await this.codec.issueReauthenticationBridge(
        accountId,
        clientId,
        resource,
        claims,
        authorizationGeneration,
      );
      await connection.commit();
      return bridge;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private async verifiedBridge(
    accountId: string,
    clientId: string,
    resource: string,
    bridge: ReauthenticationBridge,
  ): Promise<VerifiedReauthenticationBridge> {
    try {
      return await this.codec.verifyReauthenticationBridge(
        accountId,
        clientId,
        resource,
        bridge,
      );
    } catch {
      throw new InvalidReauthenticationProofError();
    }
  }

  private liveRetiredBridges(
    state: ConsentAuthorizationState | null,
    now: number,
  ): RetiredReauthenticationBridge[] {
    return (state?.retiredReauthenticationBridges ?? [])
      .filter((retired) => retired.expiresAt > now)
      .sort(compareRetiredBridges);
  }

  private retireBridge(
    retired: RetiredReauthenticationBridge[],
    fingerprint: string,
    expiresAt: number,
    now: number,
  ): RetiredReauthenticationBridge[] {
    if (expiresAt <= now) {
      return retired;
    }
    if (retired.some((entry) => entry.fingerprint === fingerprint)) {
      return retired;
    }
    if (
      retired.length >= this.maximumRetiredReauthenticationBridges
    ) {
      throw new ReauthenticationBridgeCapacityError();
    }
    return [...retired, { fingerprint, expiresAt }].sort(
      compareRetiredBridges,
    );
  }

  private async writeStateLocked(
    connection: PoolConnection,
    accountId: string,
    state: ConsentAuthorizationState,
    options?: ConsentSealOptions,
  ): Promise<void> {
    const value = await this.codec.seal(accountId, state, options);
    const active = state.lifecycle === "active";
    await connection.execute(
      `INSERT INTO consents (
         account_id, client_id, scopes, created_at, revoked_at
       ) VALUES (
         UNHEX(REPLACE(?, '-', '')), ?, ?, UTC_TIMESTAMP(6),
         IF(?, NULL, UTC_TIMESTAMP(6))
       )
       ON DUPLICATE KEY UPDATE
         scopes = VALUES(scopes),
         revoked_at = IF(?, NULL, COALESCE(revoked_at, UTC_TIMESTAMP(6)))`,
      [accountId, state.clientId, value, active, active],
    );
  }

  private async insertStateIfAbsent(
    connection: PoolConnection,
    accountId: string,
    state: ConsentAuthorizationState,
  ): Promise<void> {
    const value = await this.codec.seal(accountId, state);
    const active = state.lifecycle === "active";
    await connection.execute(
      `INSERT IGNORE INTO consents (
         account_id, client_id, scopes, created_at, revoked_at
       ) VALUES (
         UNHEX(REPLACE(?, '-', '')), ?, ?, UTC_TIMESTAMP(6),
         IF(?, NULL, UTC_TIMESTAMP(6))
       )`,
      [accountId, state.clientId, value, active],
    );
  }

  private async lockConsent(
    connection: PoolConnection,
    accountId: string,
    clientId: string,
    accountActive: boolean,
  ): Promise<ConsentAuthorizationState | null> {
    const [rows] = await connection.execute<ConsentRow[]>(
      `SELECT client_id AS clientId, CAST(scopes AS CHAR) AS value,
              ? AS accountActive
       FROM consents
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?
       FOR UPDATE`,
      [accountActive, accountId, clientId],
    );
    return rows[0] === undefined
      ? null
      : this.codec.parse(accountId, rows[0]);
  }

  private async lockAccountRow(
    connection: PoolConnection,
    accountId: string,
  ): Promise<boolean> {
    const [rows] = await connection.execute<AccountLockRow[]>(
      `SELECT 1 AS present
       FROM accounts
       WHERE id = UNHEX(REPLACE(?, '-', ''))
       FOR UPDATE`,
      [accountId],
    );
    return rows[0] !== undefined;
  }

  async getStored(
    accountId: string,
    clientId: string,
  ): Promise<ConsentAuthorizationState | null> {
    if (!validAccountId(accountId)) {
      return null;
    }
    const [rows] = await this.pool.execute<ConsentRow[]>(
      `SELECT c.client_id AS clientId, CAST(c.scopes AS CHAR) AS value,
              (a.revoked_at IS NULL) AS accountActive
       FROM consents c
       INNER JOIN accounts a ON a.id = c.account_id
       WHERE c.account_id = UNHEX(REPLACE(?, '-', ''))
         AND c.client_id = ?`,
      [accountId, clientId],
    );
    return rows[0] === undefined
      ? null
      : this.codec.parse(accountId, rows[0]);
  }

  async getActive(
    accountId: string,
    clientId: string,
  ): Promise<ConsentAuthorizationState | null> {
    const state = await this.getStored(accountId, clientId);
    return state?.accountActive === true &&
      state.lifecycle === "active" &&
      state.needsQuarantine !== true
      ? state
      : null;
  }

  async stagePendingReauthentication(
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
    bridge: ReauthenticationBridge,
    now: number,
  ): Promise<ConsentAuthorizationState> {
    if (
      !validAccountId(accountId) ||
      clientId === "" ||
      resource === "" ||
      sessionUid === ""
    ) {
      throw new InvalidReauthenticationProofError();
    }
    const verifiedBridge = await this.verifiedBridge(
      accountId,
      clientId,
      resource,
      bridge,
    );
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const account =
        await this.accountRepository.getAuthorizationEpochLocked(
          connection,
          accountId,
        );
      if (
        account === null ||
        account.authorizationEpoch !== verifiedBridge.authorizationEpoch ||
        verifiedBridge.expiresAt <= now
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
      if (
        existing === null ||
        existing.authorizationGeneration !==
          verifiedBridge.authorizationGeneration
      ) {
        throw new InvalidReauthenticationProofError();
      }
      if (existing?.needsQuarantine === true) {
        const quarantined: ConsentAuthorizationState = {
          ...existing,
          lifecycle: "quarantined",
          accountActive: !account.revoked,
          needsQuarantine: false,
        };
        await this.writeStateLocked(connection, accountId, quarantined, {
          evidence: existing.quarantineEvidence ?? "",
        });
        await connection.commit();
        return quarantined;
      }
      if (
        existing?.lifecycle === "quarantined" ||
        existing?.lifecycle === "cleanup_pending" ||
        existing?.lifecycle === "cleanup_finalizing"
      ) {
        await connection.commit();
        return existing;
      }
      let retiredReauthenticationBridges = this.liveRetiredBridges(
        existing,
        now,
      );
      if (
        retiredReauthenticationBridges.some(
          (retired) =>
            retired.fingerprint === verifiedBridge.fingerprint,
        )
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const liveAuthority =
        existing.lifecycle === "active" ||
        existing.lifecycle === "pending_reauth"
          ? existing
          : null;
      const sessionIds = [...(liveAuthority?.sessionIds ?? [])];
      if (existing?.lifecycle === "pending_reauth") {
        if (
          existing.pendingBridgeFingerprint ===
          verifiedBridge.fingerprint
        ) {
          if (
            existing.pendingReauthentication?.sessionUid !== sessionUid ||
            existing.pendingAuthorizationEpoch !==
              verifiedBridge.authorizationEpoch ||
            existing.pendingReauthentication.expiresAt !==
              verifiedBridge.expiresAt
          ) {
            throw new InvalidReauthenticationProofError();
          }
          await connection.commit();
          return existing;
        }
        const displacedSessionUid =
          existing.pendingReauthentication?.sessionUid;
        if (
          displacedSessionUid !== undefined &&
          !sessionIds.includes(displacedSessionUid)
        ) {
          if (sessionIds.length >= this.maximumSessions) {
            throw new ReauthenticationBridgeCapacityError(
              "reauthentication session capacity is exhausted",
            );
          }
          sessionIds.push(displacedSessionUid);
        }
        if (
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
      }
      const pending: PendingReauthenticationAuthority = {
        bridgeFingerprint: verifiedBridge.fingerprint,
        authorizationEpoch: verifiedBridge.authorizationEpoch,
        sessionUid,
        expiresAt: verifiedBridge.expiresAt,
      };
      const state: ConsentAuthorizationState = {
        lifecycle: "pending_reauth",
        clientId,
        resource,
        scopes: liveAuthority?.scopes ?? [],
        authorizationGeneration:
          verifiedBridge.authorizationGeneration,
        ...(liveAuthority?.grantId === undefined
          ? {}
          : { grantId: liveAuthority.grantId }),
        sessionIds,
        accountActive: !account.revoked,
        pendingReauthentication: {
          sessionUid,
          expiresAt: verifiedBridge.expiresAt,
        },
        retiredReauthenticationBridges,
      };
      await this.writeStateLocked(connection, accountId, state, { pending });
      await connection.commit();
      return state;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async activatePending(
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
    bridge: ReauthenticationBridge,
    now: number,
    state: {
      scopes: readonly string[];
      grantId: string;
      sessionIds: readonly string[];
    },
  ): Promise<void> {
    const verifiedBridge = await this.verifiedBridge(
      accountId,
      clientId,
      resource,
      bridge,
    );
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const account =
        await this.accountRepository.getAuthorizationEpochLocked(
          connection,
          accountId,
        );
      if (
        account === null ||
        account.authorizationEpoch !== verifiedBridge.authorizationEpoch ||
        verifiedBridge.expiresAt <= now
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
      if (
        existing === null ||
        existing.needsQuarantine === true ||
        existing.lifecycle !== "pending_reauth" ||
        existing.authorizationGeneration !==
          verifiedBridge.authorizationGeneration ||
        existing.pendingBridgeFingerprint !==
          verifiedBridge.fingerprint ||
        existing.pendingAuthorizationEpoch !==
          verifiedBridge.authorizationEpoch ||
        existing.pendingReauthentication?.sessionUid !== sessionUid ||
        existing.pendingReauthentication.expiresAt !==
          verifiedBridge.expiresAt
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const sessionIds = [...new Set(state.sessionIds)];
      if (sessionIds.length > this.maximumSessions) {
        throw new ReauthenticationBridgeCapacityError(
          "reauthentication session capacity is exhausted",
        );
      }
      let retiredReauthenticationBridges = this.liveRetiredBridges(
        existing,
        now,
      );
      if (
        retiredReauthenticationBridges.some(
          (retired) =>
            retired.fingerprint === verifiedBridge.fingerprint,
        )
      ) {
        throw new InvalidReauthenticationProofError();
      }
      retiredReauthenticationBridges = this.retireBridge(
        retiredReauthenticationBridges,
        verifiedBridge.fingerprint,
        verifiedBridge.expiresAt,
        now,
      );
      const active: ConsentAuthorizationState = {
        lifecycle: "active",
        clientId,
        resource,
        scopes: [...state.scopes],
        authorizationGeneration:
          existing.authorizationGeneration,
        grantId: state.grantId,
        sessionIds,
        accountActive: true,
        retiredReauthenticationBridges,
      };
      await this.writeStateLocked(connection, accountId, active);
      if (account.revoked) {
        await connection.execute(
          `UPDATE accounts
           SET revoked_at = NULL, updated_at = UTC_TIMESTAMP(6)
           WHERE id = UNHEX(REPLACE(?, '-', ''))`,
          [accountId],
        );
      }
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async updateActive(
    accountId: string,
    clientId: string,
    resource: string,
    state: {
      scopes: readonly string[];
      grantId: string;
      sessionIds: readonly string[];
    },
  ): Promise<void> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const account =
        await this.accountRepository.getAuthorizationEpochLocked(
          connection,
          accountId,
        );
      if (account === null || account.revoked) {
        throw new InactiveAuthorizationAccountError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        true,
      );
      if (
        existing === null ||
        existing.needsQuarantine === true ||
        existing.lifecycle !== "active"
      ) {
        throw new InactiveAuthorizationAccountError();
      }
      const sessionIds = [...new Set(state.sessionIds)];
      if (sessionIds.length > this.maximumSessions) {
        throw new ReauthenticationBridgeCapacityError(
          "reauthentication session capacity is exhausted",
        );
      }
      await this.writeStateLocked(
        connection,
        accountId,
        {
          lifecycle: "active",
          clientId,
          resource,
          scopes: [...state.scopes],
          authorizationGeneration:
            existing.authorizationGeneration,
          grantId: state.grantId,
          sessionIds,
          accountActive: true,
          ...(existing.retiredReauthenticationBridges === undefined
            ? {}
            : {
                retiredReauthenticationBridges:
                  existing.retiredReauthenticationBridges,
              }),
          ...(existing.consumedProofDigest === undefined
            ? {}
            : { consumedProofDigest: existing.consumedProofDigest }),
        },
        {
          consumedProofDigest: existing.consumedProofDigest,
        },
      );
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async quarantine(
    accountId: string,
    clientId: string,
  ): Promise<ConsentAuthorizationState | null> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (!(await this.lockAccountRow(connection, accountId))) {
        await connection.commit();
        return null;
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        false,
      );
      if (existing === null) {
        await connection.commit();
        return null;
      }
      if (
        existing.lifecycle === "quarantined" &&
        existing.needsQuarantine !== true
      ) {
        await connection.commit();
        return existing;
      }
      const quarantined: ConsentAuthorizationState = {
        ...existing,
        lifecycle: "quarantined",
        accountActive: false,
        needsQuarantine: false,
      };
      await this.writeStateLocked(connection, accountId, quarantined, {
        evidence:
          existing.quarantineEvidence ??
          JSON.stringify({
            version: 2,
            lifecycle: existing.lifecycle,
          }),
      });
      await connection.commit();
      return quarantined;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async beginClientCleanup(
    accountId: string,
    clientId: string,
    currentSessionUid?: string,
    now = Date.now(),
  ): Promise<ConsentAuthorizationState | null> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (!(await this.lockAccountRow(connection, accountId))) {
        await connection.commit();
        return null;
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        false,
      );
      if (existing === null) {
        await connection.commit();
        return null;
      }
      if (existing.needsQuarantine === true) {
        const quarantined: ConsentAuthorizationState = {
          ...existing,
          lifecycle: "quarantined",
          accountActive: false,
          needsQuarantine: false,
        };
        await this.writeStateLocked(connection, accountId, quarantined, {
          evidence: existing.quarantineEvidence ?? "",
        });
        await connection.commit();
        return quarantined;
      }
      if (
        existing.lifecycle === "quarantined" ||
        existing.lifecycle === "revoked" ||
        existing.lifecycle === "cleanup_pending" ||
        existing.lifecycle === "cleanup_finalizing"
      ) {
        await connection.commit();
        return existing;
      }
      let retiredReauthenticationBridges = this.liveRetiredBridges(
        existing,
        now,
      );
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
      const cleanupPending: ConsentAuthorizationState = {
        ...existing,
        lifecycle: "cleanup_pending",
        sessionIds,
        accountActive: existing.accountActive,
        pendingReauthentication: undefined,
        pendingBridgeFingerprint: undefined,
        pendingAuthorizationEpoch: undefined,
        retiredReauthenticationBridges,
        consumedProofDigest: undefined,
      };
      await this.writeStateLocked(connection, accountId, cleanupPending);
      await connection.commit();
      return cleanupPending;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async stageClientCleanupFinalization(
    accountId: string,
    clientId: string,
    returnTo: string,
  ): Promise<ConsentAuthorizationState | null> {
    if (
      !validAccountId(accountId) ||
      clientId === "" ||
      returnTo === "" ||
      returnTo.length > 4_096
    ) {
      throw new CleanupPendingAuthorizationError();
    }
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (!(await this.lockAccountRow(connection, accountId))) {
        await connection.commit();
        return null;
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        false,
      );
      if (existing === null || existing.lifecycle === "revoked") {
        await connection.commit();
        return existing;
      }
      if (
        existing.lifecycle === "cleanup_finalizing" &&
        existing.cleanupReturnTo === returnTo
      ) {
        await connection.commit();
        return existing;
      }
      if (
        existing.needsQuarantine === true ||
        existing.lifecycle !== "cleanup_pending"
      ) {
        throw new CleanupPendingAuthorizationError();
      }
      const finalizing: ConsentAuthorizationState = {
        ...existing,
        lifecycle: "cleanup_finalizing",
        cleanupReturnTo: returnTo,
        pendingReauthentication: undefined,
        consumedProofDigest: undefined,
      };
      await this.writeStateLocked(connection, accountId, finalizing);
      await connection.commit();
      return finalizing;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async retainCleanupFinalizer(
    accountId: string,
    clientId: string,
    resource: string,
    currentSessionUid: string,
    bridge: ReauthenticationBridge | undefined,
    now: number,
  ): Promise<ConsentAuthorizationState> {
    if (
      !validAccountId(accountId) ||
      clientId === "" ||
      resource === "" ||
      currentSessionUid === ""
    ) {
      throw new InvalidReauthenticationProofError();
    }
    const verified =
      bridge === undefined
        ? undefined
        : await this.verifiedBridge(
            accountId,
            clientId,
            resource,
            bridge,
          );
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const account =
        await this.accountRepository.getAuthorizationEpochLocked(
          connection,
          accountId,
        );
      if (account === null) {
        throw new InvalidReauthenticationProofError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
      if (
        existing === null ||
        existing.resource !== resource ||
        existing.needsQuarantine === true ||
        (
          existing.lifecycle !== "cleanup_pending" &&
          existing.lifecycle !== "cleanup_finalizing"
        )
      ) {
        throw new InvalidReauthenticationProofError();
      }
      let retiredReauthenticationBridges = this.liveRetiredBridges(
        existing,
        now,
      );
      const alreadyRetired =
        verified !== undefined &&
        retiredReauthenticationBridges.some(
          (entry) => entry.fingerprint === verified.fingerprint,
        );
      const alreadyRetained =
        existing.sessionIds.includes(currentSessionUid);

      if (alreadyRetired && !alreadyRetained) {
        throw new InvalidReauthenticationProofError();
      }
      if (!alreadyRetained && verified === undefined) {
        throw new InvalidReauthenticationProofError();
      }
      if (verified !== undefined && !alreadyRetired) {
        if (
          verified.authorizationEpoch !== account.authorizationEpoch ||
          verified.expiresAt <= now
        ) {
          throw new InvalidReauthenticationProofError();
        }
        retiredReauthenticationBridges = this.retireBridge(
          retiredReauthenticationBridges,
          verified.fingerprint,
          verified.expiresAt,
          now,
        );
      }
      const sessionIds = alreadyRetained
        ? existing.sessionIds
        : [...existing.sessionIds, currentSessionUid];
      if (sessionIds.length > this.maximumSessions) {
        throw new ReauthenticationBridgeCapacityError(
          "reauthentication session capacity is exhausted",
        );
      }
      const retained: ConsentAuthorizationState = {
        ...existing,
        sessionIds,
        retiredReauthenticationBridges,
      };
      await this.writeStateLocked(connection, accountId, retained);
      await connection.commit();
      return retained;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async completeClientCleanup(
    accountId: string,
    clientId: string,
  ): Promise<void> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (!(await this.lockAccountRow(connection, accountId))) {
        await connection.commit();
        return;
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        false,
      );
      if (existing === null || existing.lifecycle === "revoked") {
        await connection.commit();
        return;
      }
      if (
        existing.needsQuarantine === true ||
        (
          existing.lifecycle !== "cleanup_pending" &&
          existing.lifecycle !== "cleanup_finalizing"
        )
      ) {
        throw new CleanupPendingAuthorizationError();
      }
      await this.writeStateLocked(connection, accountId, {
        lifecycle: "revoked",
        clientId,
        resource: existing.resource,
        scopes: [],
        authorizationGeneration: randomBytes(32).toString("base64url"),
        sessionIds: [],
        accountActive: existing.accountActive,
        retiredReauthenticationBridges:
          existing.retiredReauthenticationBridges ?? [],
      });
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async revokeMatchingGrant(
    accountId: string,
    clientId: string,
    resource: string,
    grantId: string,
  ): Promise<readonly string[]> {
    if (
      !validAccountId(accountId) ||
      clientId === "" ||
      resource === "" ||
      grantId === ""
    ) {
      return [];
    }
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (!(await this.lockAccountRow(connection, accountId))) {
        await connection.commit();
        return [];
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        false,
      );
      if (
        existing === null ||
        existing.needsQuarantine === true ||
        existing.resource !== resource ||
        existing.grantId !== grantId ||
        (
          existing.lifecycle !== "active" &&
          existing.lifecycle !== "pending_reauth"
        )
      ) {
        await connection.commit();
        return [];
      }
      const sessionIds = [
        ...new Set([
          ...existing.sessionIds,
          ...(existing.pendingReauthentication === undefined
            ? []
            : [existing.pendingReauthentication.sessionUid]),
        ]),
      ];
      await this.writeStateLocked(connection, accountId, {
        lifecycle: "revoked",
        clientId,
        resource,
        scopes: [],
        authorizationGeneration: randomBytes(32).toString("base64url"),
        sessionIds: [],
        accountActive: existing.accountActive,
        retiredReauthenticationBridges:
          existing.retiredReauthenticationBridges ?? [],
      });
      await connection.commit();
      return sessionIds;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async prepareAccountRevocation(
    accountId: string,
  ): Promise<ConsentAuthorizationState[]> {
    if (!validAccountId(accountId)) {
      return [];
    }
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      if (
        !(await this.accountRepository.invalidateAuthorizationLocked(
          connection,
          accountId,
        ))
      ) {
        await connection.commit();
        return [];
      }
      const [rows] = await connection.execute<ConsentRow[]>(
        `SELECT client_id AS clientId, CAST(scopes AS CHAR) AS value,
                0 AS accountActive
         FROM consents
         WHERE account_id = UNHEX(REPLACE(?, '-', ''))
         FOR UPDATE`,
        [accountId],
      );
      const prepared: ConsentAuthorizationState[] = [];
      for (const row of rows) {
        const existing = await this.codec.parse(accountId, row);
        if (existing.needsQuarantine === true) {
          const quarantined: ConsentAuthorizationState = {
            ...existing,
            lifecycle: "quarantined",
            accountActive: false,
            needsQuarantine: false,
          };
          await this.writeStateLocked(connection, accountId, quarantined, {
            evidence: existing.quarantineEvidence ?? row.value,
          });
          prepared.push(quarantined);
          continue;
        }
        if (
          existing.lifecycle === "quarantined" ||
          existing.lifecycle === "revoked" ||
          existing.lifecycle === "cleanup_finalizing"
        ) {
          prepared.push({ ...existing, accountActive: false });
          continue;
        }
        const cleanupPending: ConsentAuthorizationState = {
          ...existing,
          lifecycle: "cleanup_pending",
          sessionIds: [
            ...new Set([
              ...existing.sessionIds,
              ...(existing.pendingReauthentication === undefined
                ? []
                : [existing.pendingReauthentication.sessionUid]),
            ]),
          ],
          accountActive: false,
          pendingReauthentication: undefined,
          consumedProofDigest: undefined,
        };
        await this.writeStateLocked(connection, accountId, cleanupPending);
        prepared.push(cleanupPending);
      }
      await connection.commit();
      return prepared;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }
}

export class MariaDbAccountAuthorizationGate implements AccountAuthorizationGate {
  constructor(private readonly pool: Pool) {}

  async isAccountActive(accountId: string): Promise<boolean> {
    if (!validAccountId(accountId)) {
      return false;
    }
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT 1
       FROM accounts
       WHERE id = UNHEX(REPLACE(?, '-', '')) AND revoked_at IS NULL`,
      [accountId],
    );
    return rows[0] !== undefined;
  }

}
