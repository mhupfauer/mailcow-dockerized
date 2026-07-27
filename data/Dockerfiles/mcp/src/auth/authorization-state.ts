import { createHash, randomBytes } from "node:crypto";

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
  revoked: number;
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
  kind: "usable" | "unsafe";
  clientId: string;
  scopes: string[];
  grantId?: string;
  sessionIds: string[];
  active: boolean;
  revoked: boolean;
}

export class InactiveAuthorizationAccountError extends Error {
  constructor() {
    super("authorization account is inactive");
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

export interface ReauthenticationProofStore {
  create(accountId: string, clientId: string, resource: string): string | null;
  bindAndVerify(
    proof: string,
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
  ): boolean;
  consume(
    proof: string,
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
  ): void;
  invalidateAuthority(
    accountId: string,
    clientId: string,
    resource: string,
  ): void;
  invalidateAccount(accountId: string): void;
}

interface ReauthenticationProof {
  accountHash: string;
  authorityHash: string;
  sessionHash?: string;
  expiresAt: number;
}

export class BoundedReauthenticationProofStore implements ReauthenticationProofStore {
  private readonly proofs = new Map<string, ReauthenticationProof>();

  constructor(
    private readonly maximum: number,
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {
    if (
      !Number.isSafeInteger(maximum) ||
      maximum < 1 ||
      !Number.isSafeInteger(ttlMs) ||
      ttlMs < 1
    ) {
      throw new Error("invalid reauthentication proof policy");
    }
  }

  private hashes(
    proof: string,
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid = "",
  ): {
    accountHash: string;
    authorityHash: string;
    proofHash: string;
    sessionHash: string;
  } {
    const accountHash = createHash("sha256")
      .update(accountId, "utf8")
      .digest("base64url");
    const authorityHash = createHash("sha256")
      .update(`${accountId}\u0000${clientId}\u0000${resource}`, "utf8")
      .digest("base64url");
    const proofHash = createHash("sha256")
      .update(`${authorityHash}\u0000${proof}`, "utf8")
      .digest("base64url");
    const sessionHash = createHash("sha256")
      .update(`${authorityHash}\u0000${sessionUid}`, "utf8")
      .digest("base64url");
    return { accountHash, authorityHash, proofHash, sessionHash };
  }

  private sweep(): void {
    const currentTime = this.now();
    for (const [proofHash, proof] of this.proofs) {
      if (proof.expiresAt <= currentTime) {
        this.proofs.delete(proofHash);
      }
    }
  }

  create(accountId: string, clientId: string, resource: string): string | null {
    this.sweep();
    if (this.proofs.size >= this.maximum) {
      return null;
    }
    const proof = randomBytes(32).toString("base64url");
    const { accountHash, authorityHash, proofHash } = this.hashes(
      proof,
      accountId,
      clientId,
      resource,
    );
    this.proofs.set(proofHash, {
      accountHash,
      authorityHash,
      expiresAt: this.now() + this.ttlMs,
    });
    return proof;
  }

  bindAndVerify(
    proof: string,
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
  ): boolean {
    this.sweep();
    const { proofHash, sessionHash } = this.hashes(
      proof,
      accountId,
      clientId,
      resource,
      sessionUid,
    );
    const stored = this.proofs.get(proofHash);
    if (
      stored === undefined ||
      (stored.sessionHash !== undefined && stored.sessionHash !== sessionHash)
    ) {
      return false;
    }
    stored.sessionHash = sessionHash;
    return true;
  }

  consume(
    proof: string,
    accountId: string,
    clientId: string,
    resource: string,
    sessionUid: string,
  ): void {
    this.proofs.delete(
      this.hashes(proof, accountId, clientId, resource, sessionUid).proofHash,
    );
  }

  invalidateAuthority(
    accountId: string,
    clientId: string,
    resource: string,
  ): void {
    const { authorityHash } = this.hashes("", accountId, clientId, resource);
    for (const [proofHash, proof] of this.proofs) {
      if (proof.authorityHash === authorityHash) {
        this.proofs.delete(proofHash);
      }
    }
  }

  invalidateAccount(accountId: string): void {
    const { accountHash } = this.hashes("", accountId, "", "");
    for (const [proofHash, proof] of this.proofs) {
      if (proof.accountHash === accountHash) {
        this.proofs.delete(proofHash);
      }
    }
  }
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
  ): Promise<ConsentAuthorizationState> {
    const stored = parseStoredConsent(row.value);
    if (stored === null) {
      return {
        kind: "unsafe",
        clientId: row.clientId,
        scopes: [],
        sessionIds: [],
        active: row.active === 1,
        revoked: row.revoked === 1,
      };
    }
    if (stored.authorityEnvelope === undefined) {
      return {
        kind: "unsafe",
        clientId: row.clientId,
        scopes: stored.scopes,
        sessionIds: [],
        active: row.active === 1,
        revoked: row.revoked === 1,
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
        kind: "usable",
        clientId: row.clientId,
        scopes: stored.scopes,
        grantId: authority.grantId,
        sessionIds: [...new Set(authority.sessionIds)],
        active: row.active === 1,
        revoked: row.revoked === 1,
      };
    } catch {
      return {
        kind: "unsafe",
        clientId: row.clientId,
        scopes: stored.scopes,
        sessionIds: [],
        active: row.active === 1,
        revoked: row.revoked === 1,
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
              1 AS active, 0 AS revoked
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
              (c.revoked_at IS NOT NULL) AS revoked
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
      reauthenticate?: boolean;
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
      const [accounts] = await connection.execute<
        Array<RowDataPacket & { revoked: number }>
      >(
        `SELECT id, (revoked_at IS NOT NULL) AS revoked
         FROM accounts
         WHERE id = UNHEX(REPLACE(?, '-', ''))
         FOR UPDATE`,
        [accountId],
      );
      const account = accounts[0];
      if (
        account === undefined ||
        (account.revoked === 1 && state.reauthenticate !== true)
      ) {
        throw new InactiveAuthorizationAccountError();
      }
      if (account.revoked === 1) {
        await connection.execute(
          `UPDATE accounts
           SET revoked_at = NULL, updated_at = UTC_TIMESTAMP(6)
           WHERE id = UNHEX(REPLACE(?, '-', ''))`,
          [accountId],
        );
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
              (c.revoked_at IS NOT NULL) AS revoked
       FROM consents c
       INNER JOIN accounts a ON a.id = c.account_id
       WHERE c.account_id = UNHEX(REPLACE(?, '-', ''))`,
      [accountId],
    );
    const states = await Promise.all(
      rows.map((row) => this.parseRow(accountId, row)),
    );
    return states;
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
    private readonly authorityMutations: AuthorizationMutationCoordinator,
    private readonly reauthenticationProofs: ReauthenticationProofStore,
    private readonly resource: string,
  ) {}

  async revokeCredential(accountId: string): Promise<void> {
    await this.accountRepository.markCredentialRejected(accountId);
    this.reauthenticationProofs.invalidateAccount(accountId);
    const states = await this.consentRepository.listStored(accountId);
    let cleanupFailed = false;
    for (const state of states) {
      this.reauthenticationProofs.invalidateAuthority(
        accountId,
        state.clientId,
        this.resource,
      );
      const lease = await this.authorityMutations.acquire(
        accountId,
        state.clientId,
        this.resource,
      );
      if (lease === null) {
        cleanupFailed = true;
        continue;
      }
      try {
        await revokeProviderAuthorityBestEffort(
          this.provider,
          state.grantId === undefined ? [] : [state.grantId],
          state.sessionIds,
        );
        await this.consentRepository.revoke(accountId, state.clientId);
      } catch {
        cleanupFailed = true;
      } finally {
        lease.release();
      }
    }
    if (cleanupFailed) {
      throw new Error("unable to revoke account authorization");
    }
  }
}
