import { GenericContainer } from "testcontainers";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  test,
  vi,
} from "vitest";

import { MariaDbAccountRepository } from "../../src/auth/account-repository.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";
import { initializeDatabase } from "../../src/db/init.js";
import { runMigrations } from "../../src/db/migrations.js";
import { createPool } from "../../src/db/pool.js";

const rootPassword = "root-password-for-account-repository-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const databasePassword = "database-password-for-account-repository-test";
const encryptionKey = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const appPassword = "app-password-not-for-errors";

describe("MariaDbAccountRepository", () => {
  let container: Awaited<ReturnType<GenericContainer["start"]>>;
  let pool: ReturnType<typeof createPool>;
  let repository: MariaDbAccountRepository;

  beforeAll(async () => {
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();
    const host = container.getHost();
    const port = container.getMappedPort(3306);

    await initializeDatabase({
      host,
      port,
      rootPassword,
      databaseName,
      databaseUser,
      databasePassword,
    });
    pool = createPool({
      host,
      port,
      database: databaseName,
      user: databaseUser,
      password: databasePassword,
    });
    await runMigrations(pool);
    repository = new MariaDbAccountRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
  }, 120_000);

  afterEach(async () => {
    await pool.query("DELETE FROM accounts");
  });

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  test("stores only an encrypted normalized credential and returns it by UUID", async () => {
    const accountId = await repository.upsertVerified(
      "CaseSensitive.Local+Folder@EXAMPLE.TEST",
      appPassword,
    );

    expect(accountId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    await expect(repository.getCredential(accountId)).resolves.toEqual({
      accountId,
      mailbox: "CaseSensitive.Local+Folder@example.test",
      appPassword,
    });

    const [rows] = await pool.query<{
      idLength: number;
      mailbox: string;
      envelope: string;
      credentialVersion: number;
    }[]>(`
      SELECT
        OCTET_LENGTH(id) AS idLength,
        mailbox_normalized AS mailbox,
        credential_envelope AS envelope,
        credential_version AS credentialVersion
      FROM accounts
    `);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      idLength: 16,
      mailbox: "CaseSensitive.Local+Folder@example.test",
      credentialVersion: 2,
    });
    expect(rows[0]?.envelope).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    expect(rows[0]?.envelope).not.toContain(appPassword);
    expect(rows[0]?.envelope).not.toContain("CaseSensitive.Local+Folder");
  });

  test("updates the existing normalized mailbox in place on reauthorization", async () => {
    const initialId = await repository.upsertVerified(
      "CaseSensitive.Local@EXAMPLE.TEST",
      "first-app-password",
    );
    const reauthorizedId = await repository.upsertVerified(
      "CaseSensitive.Local@example.test",
      "replacement-app-password",
    );

    expect(reauthorizedId).toBe(initialId);
    await expect(repository.getCredential(initialId)).resolves.toEqual({
      accountId: initialId,
      mailbox: "CaseSensitive.Local@example.test",
      appPassword: "replacement-app-password",
    });
    const [rows] = await pool.query<{ count: number }[]>(
      "SELECT COUNT(*) AS count FROM accounts",
    );
    expect(rows).toEqual([{ count: 1 }]);
  });

  test("keeps local-part case variants as separate credential accounts", async () => {
    const upperCaseLocalId = await repository.upsertVerified(
      "Case@example.test",
      "upper-case-local-password",
    );
    const lowerCaseLocalId = await repository.upsertVerified(
      "case@EXAMPLE.TEST",
      "lower-case-local-password",
    );

    expect(lowerCaseLocalId).not.toBe(upperCaseLocalId);
    await expect(repository.getCredential(upperCaseLocalId)).resolves.toEqual({
      accountId: upperCaseLocalId,
      mailbox: "Case@example.test",
      appPassword: "upper-case-local-password",
    });
    await expect(repository.getCredential(lowerCaseLocalId)).resolves.toEqual({
      accountId: lowerCaseLocalId,
      mailbox: "case@example.test",
      appPassword: "lower-case-local-password",
    });
  });

  test("atomically resolves concurrent reauthorizations to one account", async () => {
    const accountIds = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        repository.upsertVerified(
          "Concurrent.Local@EXAMPLE.TEST",
          `concurrent-password-${index}`,
        ),
      ),
    );

    expect(new Set(accountIds)).toEqual(new Set([accountIds[0]]));
    const [rows] = await pool.query<{ count: number }[]>(
      "SELECT COUNT(*) AS count FROM accounts WHERE mailbox_normalized = ?",
      ["Concurrent.Local@example.test"],
    );
    expect(rows).toEqual([{ count: 1 }]);
  });

  test("treats rejected credentials as revoked until successful reauthorization", async () => {
    const accountId = await repository.upsertVerified(
      "revoked.local@EXAMPLE.TEST",
      "original-password",
    );

    await repository.markCredentialRejected(accountId);
    await expect(repository.getCredential(accountId)).resolves.toBeNull();

    const reauthorizedId = await repository.upsertVerified(
      "revoked.local@example.test",
      "reauthorized-password",
    );
    expect(reauthorizedId).toBe(accountId);
    await expect(repository.getCredential(accountId)).resolves.toEqual({
      accountId,
      mailbox: "revoked.local@example.test",
      appPassword: "reauthorized-password",
    });
  });

  test("makes the prior authorization epoch unreadable when rotation fails", async () => {
    const vault = new AesGcmCredentialVault(encryptionKey);
    const isolatedRepository = new MariaDbAccountRepository(pool, vault);
    const verified = await isolatedRepository.upsertVerifiedForAuthorization(
      "rotation-failure@example.test",
      "verified-password",
    );
    const seal = vi
      .spyOn(vault, "seal")
      .mockRejectedValueOnce(new Error("vault unavailable"));

    await isolatedRepository.markCredentialRejected(verified.accountId);
    seal.mockRestore();

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await expect(
        isolatedRepository.getAuthorizationEpochLocked(
          connection,
          verified.accountId,
        ),
      ).rejects.toThrow("unable to open credential envelope");
      await connection.rollback();
    } finally {
      connection.release();
    }
    await expect(
      isolatedRepository.getCredential(verified.accountId),
    ).resolves.toBeNull();
  });

  test("returns null for an unknown or malformed account identifier", async () => {
    await expect(
      repository.getCredential("f4e2d9b7-44e4-4769-81e7-df4b2c3364f6"),
    ).resolves.toBeNull();
    await expect(repository.getCredential("not-a-uuid")).resolves.toBeNull();
  });

  test("normalizes the v1 ASCII mailbox contract without changing local-part case", async () => {
    const cases = [
      { mailbox: "Case.Local+Folder@EXAMPLE.TEST", normalized: "Case.Local+Folder@example.test" },
      { mailbox: '"Quoted Local"@EXAMPLE.TEST', normalized: '"Quoted Local"@example.test' },
      { mailbox: '"Escaped\\\\Backslash"@EXAMPLE.TEST', normalized: '"Escaped\\\\Backslash"@example.test' },
    ];

    for (const { mailbox, normalized } of cases) {
      const accountId = await repository.upsertVerified(mailbox, appPassword);

      await expect(repository.getCredential(accountId)).resolves.toEqual({
        accountId,
        mailbox: normalized,
        appPassword,
      });
    }
  });

  test("rejects ambiguous and unsupported v1 mailbox forms without exposing the password", async () => {
    const cases = [
      "One <one@example.test>",
      "one@example.test, two@example.test",
      "missing-domain@",
      "@missing-local.example.test",
      " case@example.test",
      "case@example.test ",
      "two words@example.test",
      '"control\u0001"@example.test',
      '"line\u2028separator"@example.test',
      "müller@example.test",
      '"bad\\\u0001escape"@example.test',
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.test",
      "local@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test",
    ];

    for (const mailbox of cases) {
      let error: unknown;

      try {
        await repository.upsertVerified(mailbox, appPassword);
      } catch (caught) {
        error = caught;
      }

      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe("invalid mailbox address");
      expect((error as Error).message).not.toContain(appPassword);
    }
  });
});
