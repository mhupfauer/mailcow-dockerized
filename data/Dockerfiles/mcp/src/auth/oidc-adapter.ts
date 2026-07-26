import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type {
  Adapter,
  AdapterFactory,
  AdapterPayload,
} from "oidc-provider";
import type { Pool, RowDataPacket } from "mysql2/promise";

import {
  AesGcmCredentialVault,
  type CredentialVault,
} from "./crypto-vault.js";

const maximumExpiry = "9999-12-31 23:59:59.999999";
const grantBearingModels = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
]);

interface StoredEnvelope {
  version: 1;
  payload: string;
  idByUserCode?: string;
  idByUid?: string;
}

interface StoredRow extends RowDataPacket {
  idHash?: Buffer;
  payloadJson: string;
  consumedEpoch: number | null;
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function primaryHash(model: string, id: string): Buffer {
  return sha256(`${model}:${id}`);
}

function deriveLookupHashKey(masterKey: Uint8Array): Buffer {
  return createHmac("sha256", masterKey)
    .update("mailcow-mcp:oidc-lookup:v1", "utf8")
    .digest();
}

function secondaryHash(
  lookupHashKey: Uint8Array,
  domain: "grant" | "user-code" | "uid",
  value: string,
): Buffer {
  return createHmac("sha256", lookupHashKey)
    .update(`${domain}:${value}`, "utf8")
    .digest();
}

function payloadRecordType(model: string): string {
  return `oidc-object:${model}`;
}

function userCodeRecordType(model: string): string {
  return `oidc-object-id-by-user-code:${model}`;
}

function uidRecordType(model: string): string {
  return `oidc-object-id-by-uid:${model}`;
}

function readEncryptionKey(env: NodeJS.ProcessEnv): Buffer {
  const value = env.MCP_ENCRYPTION_KEY;

  if (value === undefined || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("MCP_ENCRYPTION_KEY must be 64 hexadecimal characters");
  }

  return Buffer.from(value, "hex");
}

function parseStoredEnvelope(value: string): StoredEnvelope {
  try {
    const parsed: unknown = JSON.parse(value);

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      (parsed as Record<string, unknown>).version !== 1 ||
      typeof (parsed as Record<string, unknown>).payload !== "string" ||
      (
        (parsed as Record<string, unknown>).idByUserCode !== undefined &&
        typeof (parsed as Record<string, unknown>).idByUserCode !== "string"
      ) ||
      (
        (parsed as Record<string, unknown>).idByUid !== undefined &&
        typeof (parsed as Record<string, unknown>).idByUid !== "string"
      )
    ) {
      throw new Error("invalid stored envelope");
    }

    return parsed as StoredEnvelope;
  } catch {
    throw new Error("invalid stored OIDC object");
  }
}

function parsePayload(value: Uint8Array): AdapterPayload {
  try {
    const payload: unknown = JSON.parse(Buffer.from(value).toString("utf8"));

    if (
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload)
    ) {
      throw new Error("invalid payload");
    }

    return payload as AdapterPayload;
  } catch {
    throw new Error("invalid stored OIDC object");
  }
}

function expiryMicroseconds(expiresIn: number | undefined): number | null {
  if (expiresIn === undefined) {
    return null;
  }
  if (!Number.isFinite(expiresIn) || expiresIn < 0) {
    throw new Error("OIDC object expiry must be a non-negative number");
  }

  const microseconds = Math.ceil(expiresIn * 1_000_000);
  if (!Number.isSafeInteger(microseconds)) {
    throw new Error("OIDC object expiry is too large");
  }

  return microseconds;
}

export class MariaDbOidcAdapter implements Adapter {
  private constructor(
    private readonly pool: Pool,
    private readonly model: string,
    private readonly vault: CredentialVault,
    private readonly lookupHashKey: Buffer,
  ) {}

  static factory(
    pool: Pool,
    encryptionKey: Uint8Array = readEncryptionKey(process.env),
  ): AdapterFactory {
    const masterKey = Buffer.from(encryptionKey);
    const vault = new AesGcmCredentialVault(masterKey);
    const lookupHashKey = deriveLookupHashKey(masterKey);

    return (model: string): Adapter =>
      new MariaDbOidcAdapter(pool, model, vault, lookupHashKey);
  }

  async upsert(
    id: string,
    payload: AdapterPayload,
    expiresIn?: number,
  ): Promise<void> {
    const userCode =
      typeof payload.userCode === "string" ? payload.userCode : undefined;
    const uid = typeof payload.uid === "string" ? payload.uid : undefined;
    const grantId =
      grantBearingModels.has(this.model) &&
      typeof payload.grantId === "string" &&
      payload.grantId !== ""
        ? payload.grantId
        : undefined;
    const storedEnvelope: StoredEnvelope = {
      version: 1,
      payload: await this.vault.seal(
        payloadRecordType(this.model),
        id,
        Buffer.from(JSON.stringify(payload), "utf8"),
      ),
    };

    if (userCode !== undefined) {
      storedEnvelope.idByUserCode = await this.vault.seal(
        userCodeRecordType(this.model),
        userCode,
        Buffer.from(id, "utf8"),
      );
    }
    if (uid !== undefined) {
      storedEnvelope.idByUid = await this.vault.seal(
        uidRecordType(this.model),
        uid,
        Buffer.from(id, "utf8"),
      );
    }

    const expiry = expiryMicroseconds(expiresIn);
    await this.pool.execute(
      `INSERT INTO oidc_objects (
        model, id_hash, payload_json, grant_id, user_code_hash, uid_hash,
        consumed_at, expires_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, NULL,
        COALESCE(
          TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
          CAST(? AS DATETIME(6))
        )
      )
      ON DUPLICATE KEY UPDATE
        payload_json = VALUES(payload_json),
        grant_id = VALUES(grant_id),
        user_code_hash = VALUES(user_code_hash),
        uid_hash = VALUES(uid_hash),
        consumed_at = NULL,
        expires_at = VALUES(expires_at)`,
      [
        this.model,
        primaryHash(this.model, id),
        JSON.stringify(storedEnvelope),
        grantId === undefined
          ? null
          : secondaryHash(this.lookupHashKey, "grant", grantId),
        userCode === undefined
          ? null
          : secondaryHash(this.lookupHashKey, "user-code", userCode),
        uid === undefined
          ? null
          : secondaryHash(this.lookupHashKey, "uid", uid),
        expiry,
        maximumExpiry,
      ],
    );
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const [rows] = await this.pool.execute<StoredRow[]>(
      `SELECT
        CAST(payload_json AS CHAR) AS payloadJson,
        FLOOR(UNIX_TIMESTAMP(consumed_at)) AS consumedEpoch
      FROM oidc_objects
      WHERE model = ?
        AND id_hash = ?
        AND expires_at > UTC_TIMESTAMP(6)
      LIMIT 1`,
      [this.model, primaryHash(this.model, id)],
    );
    const row = rows[0];

    if (row === undefined) {
      return undefined;
    }

    return this.restorePayload(row, id);
  }

  async findByUserCode(
    userCode: string,
  ): Promise<AdapterPayload | undefined> {
    const [rows] = await this.pool.execute<StoredRow[]>(
      `SELECT
        id_hash AS idHash,
        CAST(payload_json AS CHAR) AS payloadJson,
        FLOOR(UNIX_TIMESTAMP(consumed_at)) AS consumedEpoch
      FROM oidc_objects
      WHERE model = ?
        AND user_code_hash = ?
        AND expires_at > UTC_TIMESTAMP(6)
      LIMIT 2`,
      [
        this.model,
        secondaryHash(this.lookupHashKey, "user-code", userCode),
      ],
    );
    if (rows.length > 1) {
      throw new Error("ambiguous OIDC secondary lookup");
    }
    const row = rows[0];
    if (row === undefined || row.idHash === undefined) {
      return undefined;
    }

    const storedEnvelope = parseStoredEnvelope(row.payloadJson);
    if (storedEnvelope.idByUserCode === undefined) {
      return undefined;
    }

    const id = Buffer.from(
      await this.vault.open(
        userCodeRecordType(this.model),
        userCode,
        storedEnvelope.idByUserCode,
      ),
    ).toString("utf8");

    if (
      row.idHash.length !== 32 ||
      !timingSafeEqual(row.idHash, primaryHash(this.model, id))
    ) {
      throw new Error("invalid stored OIDC object");
    }

    return this.restorePayload(row, id, storedEnvelope);
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const [rows] = await this.pool.execute<StoredRow[]>(
      `SELECT
        id_hash AS idHash,
        CAST(payload_json AS CHAR) AS payloadJson,
        FLOOR(UNIX_TIMESTAMP(consumed_at)) AS consumedEpoch
      FROM oidc_objects
      WHERE model = ?
        AND uid_hash = ?
        AND expires_at > UTC_TIMESTAMP(6)
      LIMIT 2`,
      [this.model, secondaryHash(this.lookupHashKey, "uid", uid)],
    );
    if (rows.length > 1) {
      throw new Error("ambiguous OIDC secondary lookup");
    }
    const row = rows[0];
    if (row === undefined || row.idHash === undefined) {
      return undefined;
    }

    const storedEnvelope = parseStoredEnvelope(row.payloadJson);
    if (storedEnvelope.idByUid === undefined) {
      return undefined;
    }

    const id = Buffer.from(
      await this.vault.open(
        uidRecordType(this.model),
        uid,
        storedEnvelope.idByUid,
      ),
    ).toString("utf8");

    if (
      row.idHash.length !== 32 ||
      !timingSafeEqual(row.idHash, primaryHash(this.model, id))
    ) {
      throw new Error("invalid stored OIDC object");
    }

    return this.restorePayload(row, id, storedEnvelope);
  }

  async consume(id: string): Promise<void> {
    await this.pool.execute(
      `UPDATE oidc_objects
      SET consumed_at = COALESCE(consumed_at, UTC_TIMESTAMP(6))
      WHERE model = ?
        AND id_hash = ?
        AND expires_at > UTC_TIMESTAMP(6)`,
      [this.model, primaryHash(this.model, id)],
    );
  }

  async destroy(id: string): Promise<void> {
    await this.pool.execute(
      `DELETE FROM oidc_objects
      WHERE model = ? AND id_hash = ?`,
      [this.model, primaryHash(this.model, id)],
    );
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const connection = await this.pool.getConnection();

    try {
      await connection.beginTransaction();
      await connection.execute(
        "DELETE FROM oidc_objects WHERE grant_id = ?",
        [secondaryHash(this.lookupHashKey, "grant", grantId)],
      );
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private async restorePayload(
    row: StoredRow,
    id: string,
    storedEnvelope = parseStoredEnvelope(row.payloadJson),
  ): Promise<AdapterPayload> {
    const plaintext = await this.vault.open(
      payloadRecordType(this.model),
      id,
      storedEnvelope.payload,
    );
    const payload = parsePayload(plaintext);

    if (row.consumedEpoch === null) {
      return payload;
    }

    return {
      ...payload,
      consumed: Number(row.consumedEpoch),
    };
  }
}
