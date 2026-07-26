import {
  createHash,
  generateKeyPair,
  type KeyObject,
} from "node:crypto";

import type { JWK } from "oidc-provider";
import type { Pool, RowDataPacket } from "mysql2/promise";

import { AesGcmCredentialVault } from "./crypto-vault.js";

const signingKeyStateKey = "oidc-signing-key";
const signingKeyRecordType = "oidc-signing-key";

interface SigningKeyState {
  version: 1;
  envelope: string;
}

interface StateRow extends RowDataPacket {
  stateValue: string;
}

function generateRsaKey(): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      "rsa",
      { modulusLength: 2048 },
      (error, _publicKey, privateKey) => {
        if (error) {
          reject(error);
        } else {
          resolve(privateKey);
        }
      },
    );
  });
}

function signingKeyId(jwk: JsonWebKey): string {
  if (
    jwk.kty !== "RSA" ||
    typeof jwk.e !== "string" ||
    typeof jwk.n !== "string"
  ) {
    throw new Error("generated OIDC signing key is invalid");
  }

  return createHash("sha256")
    .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }), "utf8")
    .digest("base64url");
}

async function newPrivateJwk(): Promise<JWK> {
  const privateKey = await generateRsaKey();
  const jwk = privateKey.export({ format: "jwk" });

  return {
    ...jwk,
    alg: "RS256",
    kid: signingKeyId(jwk),
    use: "sig",
  };
}

function parseState(value: string): SigningKeyState {
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      (parsed as Record<string, unknown>).version !== 1 ||
      typeof (parsed as Record<string, unknown>).envelope !== "string"
    ) {
      throw new Error("invalid state");
    }
    return parsed as SigningKeyState;
  } catch {
    throw new Error("invalid stored OIDC signing key");
  }
}

function parsePrivateJwk(value: Uint8Array): JWK {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value).toString("utf8"));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      (parsed as Record<string, unknown>).kty !== "RSA" ||
      typeof (parsed as Record<string, unknown>).kid !== "string" ||
      typeof (parsed as Record<string, unknown>).n !== "string" ||
      typeof (parsed as Record<string, unknown>).e !== "string" ||
      typeof (parsed as Record<string, unknown>).d !== "string" ||
      typeof (parsed as Record<string, unknown>).p !== "string" ||
      typeof (parsed as Record<string, unknown>).q !== "string"
    ) {
      throw new Error("invalid key");
    }
    return parsed as JWK;
  } catch {
    throw new Error("invalid stored OIDC signing key");
  }
}

async function readState(pool: Pool): Promise<SigningKeyState | undefined> {
  const [rows] = await pool.execute<StateRow[]>(
    `SELECT CAST(state_value AS CHAR) AS stateValue
    FROM service_state
    WHERE state_key = ?
    LIMIT 1`,
    [signingKeyStateKey],
  );

  return rows[0] === undefined ? undefined : parseState(rows[0].stateValue);
}

export async function loadOrCreateSigningJwk(
  pool: Pool,
  encryptionKey: Uint8Array,
): Promise<JWK> {
  const vault = new AesGcmCredentialVault(encryptionKey);
  let state = await readState(pool);

  if (state === undefined) {
    const generated = await newPrivateJwk();
    const plaintext = Buffer.from(JSON.stringify(generated), "utf8");
    let envelope: string;
    try {
      envelope = await vault.seal(
        signingKeyRecordType,
        signingKeyStateKey,
        plaintext,
      );
    } finally {
      plaintext.fill(0);
    }

    const candidate: SigningKeyState = { version: 1, envelope };
    await pool.execute(
      `INSERT IGNORE INTO service_state (state_key, state_value)
      VALUES (?, ?)`,
      [signingKeyStateKey, JSON.stringify(candidate)],
    );
    state = await readState(pool);
    if (state === undefined) {
      throw new Error("unable to persist OIDC signing key");
    }
  }

  const plaintext = await vault.open(
    signingKeyRecordType,
    signingKeyStateKey,
    state.envelope,
  );
  try {
    return parsePrivateJwk(plaintext);
  } finally {
    Buffer.from(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength)
      .fill(0);
  }
}
