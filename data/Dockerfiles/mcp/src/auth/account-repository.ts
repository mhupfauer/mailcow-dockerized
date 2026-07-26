import { randomUUID } from "node:crypto";
import type { Pool, RowDataPacket } from "mysql2/promise";

import type { CredentialVault } from "./crypto-vault.js";

export interface StoredCredential {
  accountId: string;
  mailbox: string;
  appPassword: string;
}

export interface AccountRepository {
  upsertVerified(mailbox: string, appPassword: string): Promise<string>;
  getCredential(accountId: string): Promise<StoredCredential | null>;
  markCredentialRejected(accountId: string): Promise<void>;
}

const credentialRecordType = "mailbox-credential";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const atom = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+";
const quotedString = '"(?:[ !#-\\[\\]-~]|\\\\[ -~])+"';
const localPart = `(?:${atom}(?:\\.${atom})*|${quotedString})`;
const domain = String.raw`(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*`;
const mailboxPattern = new RegExp(`^(${localPart})@(${domain})$`);

interface AccountRow extends RowDataPacket {
  id: Buffer;
  mailbox: string;
  envelope: string;
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

function parseCredential(
  plaintext: Uint8Array,
  accountId: string,
  mailbox: string,
): StoredCredential | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(plaintext).toString("utf8"));

    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      (value as Record<string, unknown>).mailbox !== mailbox ||
      typeof (value as Record<string, unknown>).appPassword !== "string"
    ) {
      return null;
    }

    return {
      accountId,
      mailbox,
      appPassword: (value as Record<string, string>).appPassword,
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

  async upsertVerified(mailbox: string, appPassword: string): Promise<string> {
    const normalizedMailbox = normalizeMailbox(mailbox);
    const proposedId = randomUUID();
    const proposedIdBytes = uuidToBuffer(proposedId);

    if (proposedIdBytes === null) {
      throw new Error("unable to store mailbox credential");
    }

    try {
      // The insert reserves the unique mailbox atomically. A duplicate keeps
      // the original BINARY(16) id, which is then used for account-bound AAD.
      const proposedEnvelope = await this.vault.seal(
        credentialRecordType,
        proposedId,
        Buffer.from(
          JSON.stringify({ mailbox: normalizedMailbox, appPassword }),
          "utf8",
        ),
      );
      await this.pool.execute(
        `INSERT INTO accounts (
          id, mailbox_normalized, credential_envelope, credential_version,
          created_at, updated_at, revoked_at
        ) VALUES (?, ?, ?, 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), NULL)
        ON DUPLICATE KEY UPDATE id = id`,
        [proposedIdBytes, normalizedMailbox, proposedEnvelope],
      );

      const [rows] = await this.pool.execute<AccountRow[]>(
        `SELECT id
        FROM accounts
        WHERE mailbox_normalized = ?`,
        [normalizedMailbox],
      );
      const accountId = rows[0] === undefined ? null : bufferToUuid(rows[0].id);

      if (accountId === null) {
        throw new Error("missing account record");
      }

      const envelope = await this.vault.seal(
        credentialRecordType,
        accountId,
        Buffer.from(
          JSON.stringify({ mailbox: normalizedMailbox, appPassword }),
          "utf8",
        ),
      );
      await this.pool.execute(
        `UPDATE accounts
        SET credential_envelope = ?, credential_version = 1,
            updated_at = UTC_TIMESTAMP(6), revoked_at = NULL
        WHERE id = ?`,
        [envelope, uuidToBuffer(accountId)],
      );

      return accountId;
    } catch {
      throw new Error("unable to store mailbox credential");
    }
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
      const credential = parseCredential(plaintext, accountId, row.mailbox);

      if (credential === null) {
        throw new Error("invalid stored credential");
      }

      return credential;
    } catch {
      throw new Error("unable to load stored credential");
    }
  }

  async markCredentialRejected(accountId: string): Promise<void> {
    const accountIdBytes = uuidToBuffer(accountId);

    if (accountIdBytes === null) {
      return;
    }

    try {
      await this.pool.execute(
        `UPDATE accounts
        SET revoked_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6)
        WHERE id = ?`,
        [accountIdBytes],
      );
    } catch {
      throw new Error("unable to revoke mailbox credential");
    }
  }
}

export { normalizeMailbox };
