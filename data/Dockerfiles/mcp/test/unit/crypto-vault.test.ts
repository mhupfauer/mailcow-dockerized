import { describe, expect, test } from "vitest";

import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";

const primaryKey = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const alternateKey = Buffer.from(
  "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100",
  "hex",
);
const accountId = "39f34a95-30db-4cda-b4d4-5a1ad8eb6b4a";
const recordType = "mailbox-credential";
const secretJson = Buffer.from(
  '{"mailbox":"CaseSensitive@example.test","appPassword":"not-for-errors"}',
  "utf8",
);

async function expectGenericOpenFailure(operation: () => Promise<unknown>): Promise<void> {
  let error: unknown;

  try {
    await operation();
  } catch (caught) {
    error = caught;
  }

  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toBe("unable to open credential envelope");
  expect((error as Error).message).not.toContain("not-for-errors");
}

describe("AesGcmCredentialVault", () => {
  test("round-trips bytes in a versioned AES-GCM envelope", async () => {
    const vault = new AesGcmCredentialVault(primaryKey);

    const envelope = await vault.seal(recordType, accountId, secretJson);

    expect(envelope).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    await expect(vault.open(recordType, accountId, envelope)).resolves.toEqual(secretJson);
  });

  test("uses a fresh nonce for each encryption", async () => {
    const vault = new AesGcmCredentialVault(primaryKey);

    const first = await vault.seal(recordType, accountId, secretJson);
    const second = await vault.seal(recordType, accountId, secretJson);

    expect(first).not.toBe(second);
    expect(first.split(".")[1]).not.toBe(second.split(".")[1]);
  });

  test("rejects an envelope opened with a different key", async () => {
    const envelope = await new AesGcmCredentialVault(primaryKey).seal(
      recordType,
      accountId,
      secretJson,
    );

    await expectGenericOpenFailure(() =>
      new AesGcmCredentialVault(alternateKey).open(recordType, accountId, envelope),
    );
  });

  test("rejects an envelope bound to a different account", async () => {
    const envelope = await new AesGcmCredentialVault(primaryKey).seal(
      recordType,
      accountId,
      secretJson,
    );

    await expectGenericOpenFailure(() =>
      new AesGcmCredentialVault(primaryKey).open(
        recordType,
        "7b7dc21f-80d5-4c35-8f86-364bca0c9d2a",
        envelope,
      ),
    );
  });

  test("rejects an envelope bound to a different record type", async () => {
    const envelope = await new AesGcmCredentialVault(primaryKey).seal(
      recordType,
      accountId,
      secretJson,
    );

    await expectGenericOpenFailure(() =>
      new AesGcmCredentialVault(primaryKey).open("handle", accountId, envelope),
    );
  });

  test("rejects malformed base64url and invalid envelope lengths", async () => {
    const vault = new AesGcmCredentialVault(primaryKey);

    await expectGenericOpenFailure(() =>
      vault.open(recordType, accountId, "v1.aaaaaaaaaaaaaaaa.%%not-base64%%"),
    );
    await expectGenericOpenFailure(() =>
      vault.open(recordType, accountId, "v1.aaaaaaaaaaaaaaa.AA"),
    );
    await expectGenericOpenFailure(() =>
      vault.open(recordType, accountId, "v1.aaaaaaaaaaaaaaaa.AA"),
    );
  });

  test("rejects an envelope with a modified authentication tag", async () => {
    const vault = new AesGcmCredentialVault(primaryKey);
    const envelope = await vault.seal(recordType, accountId, secretJson);
    const [version, nonce, ciphertextAndTag] = envelope.split(".");
    const modifiedBytes = Buffer.from(ciphertextAndTag!, "base64url");
    modifiedBytes[modifiedBytes.length - 1] ^= 1;
    const modifiedTag = `${version}.${nonce}.${modifiedBytes.toString("base64url")}`;

    await expectGenericOpenFailure(() =>
      vault.open(recordType, accountId, modifiedTag),
    );
  });

  test("rejects an unknown envelope version before attempting decryption", async () => {
    const vault = new AesGcmCredentialVault(primaryKey);

    await expectGenericOpenFailure(() =>
      vault.open(recordType, accountId, "v2.aaaaaaaaaaaaaaaa.AA"),
    );
  });
});
