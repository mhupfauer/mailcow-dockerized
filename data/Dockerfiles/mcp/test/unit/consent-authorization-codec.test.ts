import { describe, expect, test } from "vitest";

import { ConsentAuthorizationCodec } from "../../src/auth/consent-authorization-codec.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";

const encryptionKey = Buffer.from(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  "hex",
);
const accountId = "68d84f89-0f41-4d3a-a069-50c383e7b26f";
const clientId = "test-client";
const resource = "https://mail.example.test/mcp";

describe("ConsentAuthorizationCodec", () => {
  test("quarantines outer metadata tamper while retaining authenticated cleanup handles", async () => {
    const codec = new ConsentAuthorizationCodec(
      new AesGcmCredentialVault(encryptionKey),
      resource,
    );
    const encoded = await codec.seal(accountId, {
      lifecycle: "active",
      clientId,
      resource,
      scopes: ["mail.read"],
      grantId: "grant-id",
      sessionIds: ["stable-session-uid"],
      accountActive: true,
    });
    const tampered = JSON.stringify({
      ...(JSON.parse(encoded) as Record<string, unknown>),
      lifecycle: "revoked",
      scopes: ["mail.send"],
    });

    const parsed = await codec.parse(accountId, {
      clientId,
      value: tampered,
      accountActive: 1,
    });

    expect(parsed).toMatchObject({
      lifecycle: "quarantined",
      resource,
      scopes: ["mail.read"],
      grantId: "grant-id",
      sessionIds: ["stable-session-uid"],
      quarantineEvidence: tampered,
      needsQuarantine: true,
    });
  });

  test("refuses to seal authority for a different resource", async () => {
    const codec = new ConsentAuthorizationCodec(
      new AesGcmCredentialVault(encryptionKey),
      resource,
    );

    await expect(
      codec.seal(accountId, {
        lifecycle: "active",
        clientId,
        resource: "https://other.example.test/mcp",
        scopes: ["mail.read"],
        grantId: "grant-id",
        sessionIds: ["stable-session-uid"],
        accountActive: true,
      }),
    ).rejects.toThrow("invalid consent resource");
  });
});
