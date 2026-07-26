import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

export interface CredentialVault {
  seal(
    recordType: string,
    accountId: string,
    plaintext: Uint8Array,
  ): Promise<string>;
  open(
    recordType: string,
    accountId: string,
    envelope: string,
  ): Promise<Uint8Array>;
}

const envelopeVersion = "v1";
const nonceLength = 12;
const authenticationTagLength = 16;
const base64Url = /^[A-Za-z0-9_-]+$/;

function aad(recordType: string, accountId: string): Buffer {
  return Buffer.from(`mailcow-mcp:v1:${recordType}:${accountId}`, "utf8");
}

function decodeBase64Url(value: string): Buffer | null {
  if (!base64Url.test(value)) {
    return null;
  }

  const decoded = Buffer.from(value, "base64url");
  return decoded.toString("base64url") === value ? decoded : null;
}

function parseEnvelope(envelope: string): { nonce: Buffer; ciphertextAndTag: Buffer } | null {
  const parts = envelope.split(".");

  if (parts.length !== 3 || parts[0] !== envelopeVersion) {
    return null;
  }

  const nonce = decodeBase64Url(parts[1]);
  const ciphertextAndTag = decodeBase64Url(parts[2]);

  if (
    nonce === null ||
    nonce.length !== nonceLength ||
    ciphertextAndTag === null ||
    ciphertextAndTag.length < authenticationTagLength
  ) {
    return null;
  }

  return { nonce, ciphertextAndTag };
}

export class AesGcmCredentialVault implements CredentialVault {
  private readonly key: Buffer;

  constructor(key: Uint8Array) {
    if (key.length !== 32) {
      throw new Error("credential vault key must be 32 bytes");
    }

    this.key = Buffer.from(key);
  }

  async seal(
    recordType: string,
    accountId: string,
    plaintext: Uint8Array,
  ): Promise<string> {
    const nonce = randomBytes(nonceLength);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(aad(recordType, accountId));

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    return `${envelopeVersion}.${nonce.toString("base64url")}.${ciphertext.toString("base64url")}`;
  }

  async open(
    recordType: string,
    accountId: string,
    envelope: string,
  ): Promise<Uint8Array> {
    try {
      const parsed = parseEnvelope(envelope);

      if (parsed === null) {
        throw new Error("invalid credential envelope");
      }

      const ciphertextLength = parsed.ciphertextAndTag.length - authenticationTagLength;
      const ciphertext = parsed.ciphertextAndTag.subarray(0, ciphertextLength);
      const tag = parsed.ciphertextAndTag.subarray(ciphertextLength);
      const decipher = createDecipheriv("aes-256-gcm", this.key, parsed.nonce);
      decipher.setAAD(aad(recordType, accountId));
      decipher.setAuthTag(tag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new Error("unable to open credential envelope");
    }
  }
}
