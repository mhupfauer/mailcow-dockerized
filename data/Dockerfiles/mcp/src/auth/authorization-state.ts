import { createHash } from "node:crypto";

import type {
  Pool,
  PoolConnection,
  RowDataPacket,
} from "mysql2/promise";

import { MariaDbAccountRepository } from "./account-repository.js";
import {
  ConsentAuthorizationCodec,
  reauthenticationProofDigest,
  validAccountId,
  validReauthenticationBridge,
  type ConsentAuthorizationState,
  type ConsentSealOptions,
  type PendingReauthenticationAuthority,
  type ReauthenticationBridge,
} from "./consent-authorization-codec.js";
import type { CredentialVault } from "./crypto-vault.js";

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

  constructor(
    private readonly pool: Pool,
    vault: CredentialVault,
    expectedResource: string,
  ) {
    this.accountRepository = new MariaDbAccountRepository(pool, vault);
    this.codec = new ConsentAuthorizationCodec(vault, expectedResource);
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
      sessionUid === "" ||
      !validReauthenticationBridge(bridge)
    ) {
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
        account.authorizationEpoch !== bridge.authorizationEpoch ||
        bridge.expiresAt <= now
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
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
        existing?.lifecycle === "cleanup_pending"
      ) {
        await connection.commit();
        return existing;
      }
      const digest = reauthenticationProofDigest(
        bridge,
        accountId,
        clientId,
        resource,
        sessionUid,
      );
      if (
        existing?.lifecycle === "active" &&
        existing.consumedProofDigest === digest
      ) {
        await connection.commit();
        return existing;
      }
      const pending: PendingReauthenticationAuthority = {
        proofDigest: digest,
        authorizationEpoch: bridge.authorizationEpoch,
        sessionUid,
        expiresAt: bridge.expiresAt,
      };
      const state: ConsentAuthorizationState = {
        lifecycle: "pending_reauth",
        clientId,
        resource,
        scopes: existing?.scopes ?? [],
        ...(existing?.grantId === undefined
          ? {}
          : { grantId: existing.grantId }),
        sessionIds: existing?.sessionIds ?? [],
        accountActive: !account.revoked,
        pendingReauthentication: {
          sessionUid,
          expiresAt: bridge.expiresAt,
        },
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
        account.authorizationEpoch !== bridge.authorizationEpoch ||
        bridge.expiresAt <= now
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const existing = await this.lockConsent(
        connection,
        accountId,
        clientId,
        !account.revoked,
      );
      const digest = reauthenticationProofDigest(
        bridge,
        accountId,
        clientId,
        resource,
        sessionUid,
      );
      if (
        existing === null ||
        existing.needsQuarantine === true ||
        existing.lifecycle !== "pending_reauth" ||
        existing.pendingProofDigest !== digest ||
        existing.pendingAuthorizationEpoch !== bridge.authorizationEpoch ||
        existing.pendingReauthentication?.sessionUid !== sessionUid ||
        existing.pendingReauthentication.expiresAt !== bridge.expiresAt
      ) {
        throw new InvalidReauthenticationProofError();
      }
      const active: ConsentAuthorizationState = {
        lifecycle: "active",
        clientId,
        resource,
        scopes: [...state.scopes],
        grantId: state.grantId,
        sessionIds: [...state.sessionIds],
        accountActive: true,
        consumedProofDigest: digest,
      };
      await this.writeStateLocked(connection, accountId, active, {
        consumedProofDigest: digest,
      });
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
      await this.writeStateLocked(
        connection,
        accountId,
        {
          lifecycle: "active",
          clientId,
          resource,
          scopes: [...state.scopes],
          grantId: state.grantId,
          sessionIds: [...state.sessionIds],
          accountActive: true,
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
        existing.lifecycle === "cleanup_pending"
      ) {
        await connection.commit();
        return existing;
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
        accountActive: existing.accountActive,
        pendingReauthentication: undefined,
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
        existing.lifecycle !== "cleanup_pending"
      ) {
        throw new CleanupPendingAuthorizationError();
      }
      await this.writeStateLocked(connection, accountId, {
        lifecycle: "revoked",
        clientId,
        resource: existing.resource,
        scopes: existing.scopes,
        sessionIds: [],
        accountActive: existing.accountActive,
      });
      await connection.commit();
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
          existing.lifecycle === "revoked"
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
