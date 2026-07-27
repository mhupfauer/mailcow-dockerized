import { createHash } from "node:crypto";

import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Provider } from "oidc-provider";

import type { AccountRepository } from "./account-repository.js";
import type { CredentialVault } from "./crypto-vault.js";
import { MCP_OAUTH_SCOPES } from "./oidc-provider.js";

const allowedScopes = new Set<string>(MCP_OAUTH_SCOPES);
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

interface ConsentRow extends RowDataPacket {
  clientId: string;
  value: string;
  active: number;
  replacementAllowed: number;
}

interface StoredConsentV1 {
  version: 1;
  scopes: string[];
  authorityEnvelope: string;
}

interface ConsentAuthorityV1 {
  version: 1;
  clientId: string;
  grantId: string;
  sessionIds: string[];
}

export interface ConsentAuthorizationState {
  scopes: string[];
  grantId?: string;
  sessionIds: string[];
  reusable: boolean;
  active: boolean;
  replacementAllowed: boolean;
}

export class InactiveAuthorizationAccountError extends Error {
  constructor() {
    super("authorization account is inactive");
  }
}

export interface AccountAuthorizationGate {
  isAccountActive(accountId: string): Promise<boolean>;
}

function validAccountId(accountId: string): boolean {
  return uuidPattern.test(accountId);
}

function normalizeScopes(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    !value.every(
      (scope) => typeof scope === "string" && allowedScopes.has(scope),
    )
  ) {
    return null;
  }
  return [...new Set(value)].sort();
}

function authorityRecordType(clientId: string): string {
  const clientHash = createHash("sha256")
    .update(clientId, "utf8")
    .digest("base64url");
  return `consent-authority:${clientHash}`;
}

function parseStoredConsent(
  value: string,
): { scopes: string[]; authorityEnvelope?: string } | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed)) {
      const scopes = normalizeScopes(parsed);
      return scopes === null ? null : { scopes };
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      (parsed as Record<string, unknown>).version !== 1 ||
      typeof (parsed as Record<string, unknown>).authorityEnvelope !== "string"
    ) {
      return null;
    }
    const scopes = normalizeScopes((parsed as Record<string, unknown>).scopes);
    return scopes === null
      ? null
      : {
          scopes,
          authorityEnvelope: (parsed as StoredConsentV1).authorityEnvelope,
        };
  } catch {
    return null;
  }
}

function parseAuthority(
  plaintext: Uint8Array,
  clientId: string,
): ConsentAuthorityV1 | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(plaintext).toString("utf8"));
    const record =
      typeof value === "object" && value !== null
        ? (value as Record<string, unknown>)
        : undefined;
    const sessionIds = record?.sessionIds;
    if (
      record === undefined ||
      record.version !== 1 ||
      record.clientId !== clientId ||
      typeof record.grantId !== "string" ||
      record.grantId === "" ||
      !Array.isArray(sessionIds) ||
      !sessionIds.every(
        (sessionId) => typeof sessionId === "string" && sessionId !== "",
      )
    ) {
      return null;
    }
    return value as ConsentAuthorityV1;
  } catch {
    return null;
  }
}

export class MariaDbConsentAuthorizationRepository {
  constructor(
    private readonly pool: Pool,
    private readonly vault: CredentialVault,
  ) {}

  private async parseRow(
    accountId: string,
    row: ConsentRow,
  ): Promise<ConsentAuthorizationState | null> {
    const stored = parseStoredConsent(row.value);
    if (stored === null) {
      return null;
    }
    if (stored.authorityEnvelope === undefined) {
      return {
        scopes: stored.scopes,
        sessionIds: [],
        reusable: false,
        active: row.active === 1,
        replacementAllowed: row.replacementAllowed === 1,
      };
    }
    try {
      const plaintext = await this.vault.open(
        authorityRecordType(row.clientId),
        accountId,
        stored.authorityEnvelope,
      );
      const authority = parseAuthority(plaintext, row.clientId);
      if (authority === null) {
        throw new Error("invalid consent authority");
      }
      return {
        scopes: stored.scopes,
        grantId: authority.grantId,
        sessionIds: [...new Set(authority.sessionIds)],
        reusable: true,
        active: row.active === 1,
        replacementAllowed: row.replacementAllowed === 1,
      };
    } catch {
      return {
        scopes: stored.scopes,
        sessionIds: [],
        reusable: false,
        active: row.active === 1,
        replacementAllowed: row.replacementAllowed === 1,
      };
    }
  }

  async getActive(
    accountId: string,
    clientId: string,
  ): Promise<ConsentAuthorizationState | null> {
    if (!validAccountId(accountId)) {
      return null;
    }
    const [rows] = await this.pool.execute<ConsentRow[]>(
      `SELECT c.client_id AS clientId, CAST(c.scopes AS CHAR) AS value,
              1 AS active, 0 AS replacementAllowed
       FROM consents c
       INNER JOIN accounts a ON a.id = c.account_id
       WHERE c.account_id = UNHEX(REPLACE(?, '-', ''))
         AND c.client_id = ?
         AND c.revoked_at IS NULL
         AND a.revoked_at IS NULL`,
      [accountId, clientId],
    );
    return rows[0] === undefined ? null : this.parseRow(accountId, rows[0]);
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
              (c.revoked_at IS NULL AND a.revoked_at IS NULL) AS active,
              (
                c.revoked_at IS NOT NULL
                AND a.revoked_at IS NULL
                AND a.updated_at > c.revoked_at
              ) AS replacementAllowed
       FROM consents c
       INNER JOIN accounts a ON a.id = c.account_id
       WHERE c.account_id = UNHEX(REPLACE(?, '-', ''))
         AND c.client_id = ?`,
      [accountId, clientId],
    );
    return rows[0] === undefined ? null : this.parseRow(accountId, rows[0]);
  }

  async save(
    accountId: string,
    clientId: string,
    state: {
      scopes: readonly string[];
      grantId: string;
      sessionIds: readonly string[];
    },
  ): Promise<void> {
    if (!validAccountId(accountId)) {
      throw new Error("invalid account");
    }
    const scopes = normalizeScopes([...state.scopes]);
    if (
      scopes === null ||
      state.grantId === "" ||
      !state.sessionIds.every((sessionId) => sessionId !== "")
    ) {
      throw new Error("invalid consent authority");
    }
    const authority: ConsentAuthorityV1 = {
      version: 1,
      clientId,
      grantId: state.grantId,
      sessionIds: [...new Set(state.sessionIds)],
    };
    const authorityEnvelope = await this.vault.seal(
      authorityRecordType(clientId),
      accountId,
      Buffer.from(JSON.stringify(authority), "utf8"),
    );
    const stored: StoredConsentV1 = {
      version: 1,
      scopes,
      authorityEnvelope,
    };
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [accounts] = await connection.execute<RowDataPacket[]>(
        `SELECT id
         FROM accounts
         WHERE id = UNHEX(REPLACE(?, '-', '')) AND revoked_at IS NULL
         FOR UPDATE`,
        [accountId],
      );
      if (accounts[0] === undefined) {
        throw new InactiveAuthorizationAccountError();
      }
      await connection.execute(
        `INSERT INTO consents (
           account_id, client_id, scopes, created_at, revoked_at
         ) VALUES (
           UNHEX(REPLACE(?, '-', '')), ?, ?, UTC_TIMESTAMP(6), NULL
         )
         ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), revoked_at = NULL`,
        [accountId, clientId, JSON.stringify(stored)],
      );
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async revoke(accountId: string, clientId: string): Promise<void> {
    if (!validAccountId(accountId)) {
      return;
    }
    await this.pool.execute(
      `UPDATE consents SET revoked_at = UTC_TIMESTAMP(6)
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, clientId],
    );
  }

  async listStored(accountId: string): Promise<ConsentAuthorizationState[]> {
    if (!validAccountId(accountId)) {
      return [];
    }
    const [rows] = await this.pool.execute<ConsentRow[]>(
      `SELECT c.client_id AS clientId, CAST(c.scopes AS CHAR) AS value,
              (c.revoked_at IS NULL AND a.revoked_at IS NULL) AS active,
              (
                c.revoked_at IS NOT NULL
                AND a.revoked_at IS NULL
                AND a.updated_at > c.revoked_at
              ) AS replacementAllowed
       FROM consents c
       INNER JOIN accounts a ON a.id = c.account_id
       WHERE c.account_id = UNHEX(REPLACE(?, '-', ''))`,
      [accountId],
    );
    const states = await Promise.all(
      rows.map((row) => this.parseRow(accountId, row)),
    );
    return states.filter(
      (state): state is ConsentAuthorizationState => state !== null,
    );
  }

  async revokeAll(accountId: string): Promise<void> {
    if (!validAccountId(accountId)) {
      return;
    }
    await this.pool.execute(
      `UPDATE consents SET revoked_at = UTC_TIMESTAMP(6)
       WHERE account_id = UNHEX(REPLACE(?, '-', ''))`,
      [accountId],
    );
  }
}

export async function revokeProviderAuthority(
  provider: Provider,
  grantIds: readonly string[],
  sessionIds: readonly string[],
): Promise<void> {
  for (const grantId of new Set(grantIds.filter(Boolean))) {
    await Promise.all([
      provider.AccessToken.revokeByGrantId(grantId),
      provider.AuthorizationCode.revokeByGrantId(grantId),
      provider.RefreshToken.revokeByGrantId(grantId),
    ]);
    const grant = await provider.Grant.find(grantId);
    await grant?.destroy();
  }
  for (const sessionId of new Set(sessionIds.filter(Boolean))) {
    const session = await provider.Session.findByUid(sessionId);
    await session?.destroy();
  }
}

export async function revokeProviderAuthorityBestEffort(
  provider: Provider,
  grantIds: readonly string[],
  sessionIds: readonly string[],
): Promise<void> {
  const operations: Promise<unknown>[] = [];
  for (const grantId of new Set(grantIds.filter(Boolean))) {
    operations.push(
      provider.AccessToken.revokeByGrantId(grantId),
      provider.AuthorizationCode.revokeByGrantId(grantId),
      provider.RefreshToken.revokeByGrantId(grantId),
      (async () => {
        const grant = await provider.Grant.find(grantId);
        await grant?.destroy();
      })(),
    );
  }
  for (const sessionId of new Set(sessionIds.filter(Boolean))) {
    operations.push(
      (async () => {
        const session = await provider.Session.findByUid(sessionId);
        await session?.destroy();
      })(),
    );
  }
  const results = await Promise.allSettled(operations);
  if (results.some((result) => result.status === "rejected")) {
    throw new Error("unable to revoke provider authority");
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

export class MariaDbAccountAuthorizationRevoker {
  constructor(
    private readonly accountRepository: AccountRepository,
    private readonly consentRepository: MariaDbConsentAuthorizationRepository,
    private readonly provider: Provider,
  ) {}

  async revokeCredential(accountId: string): Promise<void> {
    await this.accountRepository.markCredentialRejected(accountId);
    const states = await this.consentRepository.listStored(accountId);
    await revokeProviderAuthorityBestEffort(
      this.provider,
      states.flatMap((state) =>
        state.grantId === undefined ? [] : [state.grantId],
      ),
      states.flatMap((state) => state.sessionIds),
    );
    await this.consentRepository.revokeAll(accountId);
  }
}
