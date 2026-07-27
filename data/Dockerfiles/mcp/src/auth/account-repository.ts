import { randomUUID } from "node:crypto";
import type {
  Pool,
  PoolConnection,
  RowDataPacket,
} from "mysql2/promise";

import type { CredentialVault } from "./crypto-vault.js";

export interface StoredCredential {
  accountId: string;
  mailbox: string;
  appPassword: string;
}

export interface VerifiedAuthorizationCredential {
  accountId: string;
  authorizationEpoch: string;
}

export interface AccountRepository {
  upsertVerified(mailbox: string, appPassword: string): Promise<string>;
  upsertVerifiedForAuthorization(
    mailbox: string,
    appPassword: string,
  ): Promise<VerifiedAuthorizationCredential>;
  getCredential(accountId: string): Promise<StoredCredential | null>;
  markCredentialRejected(accountId: string): Promise<void>;
}

const credentialRecordType = "mailbox-credential";
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const atom = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+";
const quotedString = '"(?:[ !#-\\[\\]-~]|\\\\[ -~])+"';
const localPart = `(?:${atom}(?:\\.${atom})*|${quotedString})`;
const domain = String.raw`(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*`;
const mailboxPattern = new RegExp(`^(${localPart})@(${domain})$`);

interface AccountRow extends RowDataPacket {
  id: Buffer;
  mailbox: string;
  envelope: string;
  revoked?: number;
}

interface StoredCredentialPayload {
  version: 2;
  mailbox: string;
  appPassword: string;
  authorizationEpoch: string;
}

function normalizeMailbox(value: string): string {
  if (
    typeof value !== "string" ||
    value === "" ||
    value !== value.trim() ||
    !/^[\x20-\x7e]+$/.test(value)
  ) {
    throw new Error("invalid mailbox address");
  }

  const match = mailboxPattern.exec(value);

  if (match === null || match[1] === undefined || match[2] === undefined) {
    throw new Error("invalid mailbox address");
  }

  const normalized = `${match[1]}@${match[2].toLowerCase()}`;

  if (
    Buffer.byteLength(match[1], "ascii") > 64 ||
    Buffer.byteLength(match[2], "ascii") > 253 ||
    Buffer.byteLength(normalized, "ascii") > 254
  ) {
    throw new Error("invalid mailbox address");
  }

  return normalized;
}

function uuidToBuffer(accountId: string): Buffer | null {
  if (!uuidPattern.test(accountId)) {
    return null;
  }

  return Buffer.from(accountId.replaceAll("-", ""), "hex");
}

function bufferToUuid(value: Buffer): string | null {
  if (value.length !== 16) {
    return null;
  }

  const hex = value.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parseCredentialPayload(
  plaintext: Uint8Array,
  mailbox: string,
): StoredCredentialPayload | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(plaintext).toString("utf8"));

    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      (value as Record<string, unknown>).mailbox !== mailbox ||
      typeof (value as Record<string, unknown>).appPassword !== "string" ||
      (
        (value as Record<string, unknown>).version !== undefined &&
        (
          (value as Record<string, unknown>).version !== 2 ||
          typeof (value as Record<string, unknown>).authorizationEpoch !==
            "string" ||
          (value as Record<string, unknown>).authorizationEpoch === ""
        )
      )
    ) {
      return null;
    }

    return {
      mailbox,
      appPassword: (value as Record<string, string>).appPassword,
      version: 2,
      authorizationEpoch:
        (value as Record<string, unknown>).version === 2
          ? ((value as Record<string, string>).authorizationEpoch as string)
          : randomUUID(),
    };
  } catch {
    return null;
  }
}

export class MariaDbAccountRepository implements AccountRepository {
  constructor(
    private readonly pool: Pool,
    private readonly vault: CredentialVault,
  ) {}

  private async storeVerified(
    mailbox: string,
    appPassword: string,
    activateAuthorization: boolean,
  ): Promise<VerifiedAuthorizationCredential> {
    const normalizedMailbox = normalizeMailbox(mailbox);
    const proposedId = randomUUID();
    const proposedIdBytes = uuidToBuffer(proposedId);
    const proposedAuthorizationEpoch = randomUUID();

    if (proposedIdBytes === null) {
      throw new Error("unable to store mailbox credential");
    }

    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const proposedEnvelope = await this.vault.seal(
        credentialRecordType,
        proposedId,
        Buffer.from(
          JSON.stringify({
            version: 2,
            mailbox: normalizedMailbox,
            appPassword,
            authorizationEpoch: proposedAuthorizationEpoch,
          } satisfies StoredCredentialPayload),
          "utf8",
        ),
      );
      // The insert reserves the unique mailbox atomically. A duplicate keeps
      // the original BINARY(16) id, which is locked before its credential is
      // replaced while preserving the current revocation generation.
      await connection.execute(
        `INSERT INTO accounts (
          id, mailbox_normalized, credential_envelope, credential_version,
          created_at, updated_at, revoked_at
        ) VALUES (
          ?, ?, ?, 2, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6),
          IF(?, NULL, UTC_TIMESTAMP(6))
        )
        ON DUPLICATE KEY UPDATE id = id`,
        [
          proposedIdBytes,
          normalizedMailbox,
          proposedEnvelope,
          activateAuthorization,
        ],
      );

      const [rows] = await connection.execute<AccountRow[]>(
        `SELECT id, mailbox_normalized AS mailbox,
                credential_envelope AS envelope,
                (revoked_at IS NOT NULL) AS revoked
        FROM accounts
        WHERE mailbox_normalized = ?
        FOR UPDATE`,
        [normalizedMailbox],
      );
      const accountId = rows[0] === undefined ? null : bufferToUuid(rows[0].id);

      if (accountId === null) {
        throw new Error("missing account record");
      }

      let authorizationEpoch: string = proposedAuthorizationEpoch;
      const existing = rows[0];
      if (existing !== undefined) {
        try {
          const plaintext = await this.vault.open(
            credentialRecordType,
            accountId,
            existing.envelope,
          );
          authorizationEpoch =
            parseCredentialPayload(plaintext, normalizedMailbox)
              ?.authorizationEpoch ?? proposedAuthorizationEpoch;
        } catch {
          // A verified credential replaces an unreadable legacy envelope with
          // a fresh authorization generation while the account lock is held.
        }
      }
      const envelope = await this.vault.seal(
        credentialRecordType,
        accountId,
        Buffer.from(
          JSON.stringify({
            version: 2,
            mailbox: normalizedMailbox,
            appPassword,
            authorizationEpoch,
          } satisfies StoredCredentialPayload),
          "utf8",
        ),
      );
      await connection.execute(
        `UPDATE accounts
        SET credential_envelope = ?, credential_version = 2,
            updated_at = UTC_TIMESTAMP(6),
            revoked_at = IF(?, NULL, revoked_at)
        WHERE id = ?`,
        [envelope, activateAuthorization, uuidToBuffer(accountId)],
      );
      await connection.commit();
      return { accountId, authorizationEpoch };
    } catch {
      await connection.rollback();
      throw new Error("unable to store mailbox credential");
    } finally {
      connection.release();
    }
  }

  async upsertVerified(mailbox: string, appPassword: string): Promise<string> {
    return (await this.storeVerified(mailbox, appPassword, true)).accountId;
  }

  async upsertVerifiedForAuthorization(
    mailbox: string,
    appPassword: string,
  ): Promise<VerifiedAuthorizationCredential> {
    return this.storeVerified(mailbox, appPassword, false);
  }

  async getAuthorizationEpochLocked(
    connection: PoolConnection,
    accountId: string,
  ): Promise<{ authorizationEpoch: string; revoked: boolean } | null> {
    const accountIdBytes = uuidToBuffer(accountId);
    if (accountIdBytes === null) {
      return null;
    }
    const [rows] = await connection.execute<AccountRow[]>(
      `SELECT id, mailbox_normalized AS mailbox,
              credential_envelope AS envelope,
              (revoked_at IS NOT NULL) AS revoked
       FROM accounts
       WHERE id = ?
       FOR UPDATE`,
      [accountIdBytes],
    );
    const row = rows[0];
    if (row === undefined || bufferToUuid(row.id) !== accountId) {
      return null;
    }
    const plaintext = await this.vault.open(
      credentialRecordType,
      accountId,
      row.envelope,
    );
    const credential = parseCredentialPayload(
      plaintext,
      row.mailbox,
    );
    if (credential === null) {
      throw new Error("invalid stored credential");
    }
    return {
      authorizationEpoch: credential.authorizationEpoch,
      revoked: row.revoked === 1,
    };
  }

  async invalidateAuthorizationLocked(
    connection: PoolConnection,
    accountId: string,
  ): Promise<boolean> {
    const accountIdBytes = uuidToBuffer(accountId);
    if (accountIdBytes === null) {
      return false;
    }
    const [rows] = await connection.execute<AccountRow[]>(
      `SELECT id, mailbox_normalized AS mailbox,
              credential_envelope AS envelope
       FROM accounts
       WHERE id = ?
       FOR UPDATE`,
      [accountIdBytes],
    );
    const row = rows[0];
    if (row === undefined || bufferToUuid(row.id) !== accountId) {
      return false;
    }
    let replacementEnvelope: string | undefined;
    try {
      const plaintext = await this.vault.open(
        credentialRecordType,
        accountId,
        row.envelope,
      );
      const credential = parseCredentialPayload(plaintext, row.mailbox);
      if (credential !== null) {
        replacementEnvelope = await this.vault.seal(
          credentialRecordType,
          accountId,
          Buffer.from(
            JSON.stringify({
              ...credential,
              authorizationEpoch: randomUUID(),
            } satisfies StoredCredentialPayload),
            "utf8",
          ),
        );
      }
    } catch {
      // Revocation must remain fail closed even when the credential envelope
      // is corrupt or the vault cannot rotate its authorization generation.
    }
    if (replacementEnvelope === undefined) {
      await connection.execute(
        `UPDATE accounts
         SET credential_envelope = ?, credential_version = 2,
             revoked_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6)
         WHERE id = ?`,
        [`revoked.${randomUUID()}`, accountIdBytes],
      );
    } else {
      await connection.execute(
        `UPDATE accounts
         SET credential_envelope = ?, credential_version = 2,
             revoked_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6)
         WHERE id = ?`,
        [replacementEnvelope, accountIdBytes],
      );
    }
    return true;
  }

  async getCredential(accountId: string): Promise<StoredCredential | null> {
    const accountIdBytes = uuidToBuffer(accountId);

    if (accountIdBytes === null) {
      return null;
    }

    try {
      const [rows] = await this.pool.execute<AccountRow[]>(
        `SELECT id, mailbox_normalized AS mailbox, credential_envelope AS envelope
        FROM accounts
        WHERE id = ? AND revoked_at IS NULL`,
        [accountIdBytes],
      );
      const row = rows[0];

      if (row === undefined || bufferToUuid(row.id) !== accountId) {
        return null;
      }

      const plaintext = await this.vault.open(
        credentialRecordType,
        accountId,
        row.envelope,
      );
      const credential = parseCredentialPayload(plaintext, row.mailbox);

      if (credential === null) {
        throw new Error("invalid stored credential");
      }

      return {
        accountId,
        mailbox: credential.mailbox,
        appPassword: credential.appPassword,
      };
    } catch {
      throw new Error("unable to load stored credential");
    }
  }

  async markCredentialRejected(accountId: string): Promise<void> {
    const accountIdBytes = uuidToBuffer(accountId);

    if (accountIdBytes === null) {
      return;
    }

    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      await this.invalidateAuthorizationLocked(connection, accountId);
      await connection.commit();
    } catch {
      await connection.rollback();
      throw new Error("unable to revoke mailbox credential");
    } finally {
      connection.release();
    }
  }
}

export { normalizeMailbox };
