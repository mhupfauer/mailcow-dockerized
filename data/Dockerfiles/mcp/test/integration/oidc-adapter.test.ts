import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AdapterPayload } from "oidc-provider";
import type { Pool, RowDataPacket } from "mysql2/promise";
import { GenericContainer } from "testcontainers";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "vitest";

import { MariaDbOidcAdapter } from "../../src/auth/oidc-adapter.js";
import { initializeDatabase } from "../../src/db/init.js";
import { runMigrations } from "../../src/db/migrations.js";
import { createPool } from "../../src/db/pool.js";

const rootPassword = "root-password-for-oidc-adapter-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const databasePassword = "database-password-for-oidc-adapter-test";
const encryptionKeyHex =
  "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const originalEncryptionKey = process.env.MCP_ENCRYPTION_KEY;
const execFileAsync = promisify(execFile);

const modelCases: readonly {
  model: string;
  id: string;
  payload: AdapterPayload;
}[] = [
  {
    model: "Session",
    id: "model-session-id-S1",
    payload: { kind: "Session", accountId: "account-1", uid: "model-session-uid-S1" },
  },
  {
    model: "AccessToken",
    id: "model-access-token-id-A2",
    payload: {
      kind: "AccessToken",
      accountId: "account-2",
      scope: "openid",
      extra: { mutableMarker: "caller-owned" },
    },
  },
  {
    model: "AuthorizationCode",
    id: "model-authorization-code-id-C3",
    payload: { kind: "AuthorizationCode", accountId: "account-3", nonce: "nonce-3" },
  },
  {
    model: "RefreshToken",
    id: "model-refresh-token-id-R4",
    payload: { kind: "RefreshToken", accountId: "account-4", rotations: 2 },
  },
  {
    model: "Grant",
    id: "model-grant-id-G5",
    payload: { kind: "Grant", accountId: "account-5", scope: "openid email" },
  },
  {
    model: "Interaction",
    id: "model-interaction-id-I6",
    payload: {
      kind: "Interaction",
      accountId: "account-6",
      params: { client_id: "client-6" },
    },
  },
  {
    model: "Client",
    id: "model-client-id-C7",
    payload: {
      client_id: "model-client-id-C7",
      redirect_uris: ["https://client.example/callback"],
    },
  },
  {
    model: "RegistrationAccessToken",
    id: "model-registration-token-id-T8",
    payload: { kind: "RegistrationAccessToken", clientId: "client-8" },
  },
  {
    model: "ReplayDetection",
    id: "model-replay-id-R9",
    payload: { kind: "ReplayDetection", jti: "model-replay-id-R9" },
  },
];

interface CountRow extends RowDataPacket {
  count: number;
}

interface ConsumedRow extends RowDataPacket {
  consumedAt: Date | null;
}

interface RawOidcRow extends RowDataPacket {
  model: string;
  idHash: string;
  payload: string;
  grantHash: string | null;
  userCodeHash: string | null;
  uidHash: string | null;
  consumedAt: string | null;
  expiresAt: string;
}

describe("MariaDbOidcAdapter", () => {
  let container: Awaited<ReturnType<GenericContainer["start"]>>;
  let pool: Pool;
  let databaseHost: string;
  let databasePort: number;

  beforeAll(async () => {
    process.env.MCP_ENCRYPTION_KEY = encryptionKeyHex;
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();

    databaseHost = container.getHost();
    databasePort = container.getMappedPort(3306);

    await initializeDatabase({
      host: databaseHost,
      port: databasePort,
      rootPassword,
      databaseName,
      databaseUser,
      databasePassword,
    });
    pool = createPool({
      host: databaseHost,
      port: databasePort,
      database: databaseName,
      user: databaseUser,
      password: databasePassword,
    });
    await runMigrations(pool);
  }, 120_000);

  beforeEach(async () => {
    const [rows] = await pool.query<CountRow[]>(
      "SELECT COUNT(*) AS count FROM oidc_objects",
    );
    expect(rows).toEqual([{ count: 0 }]);
  });

  afterEach(async () => {
    await pool.query("DELETE FROM oidc_objects");
    const [rows] = await pool.query<CountRow[]>(
      "SELECT COUNT(*) AS count FROM oidc_objects",
    );
    expect(rows).toEqual([{ count: 0 }]);
  });

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    if (originalEncryptionKey === undefined) {
      delete process.env.MCP_ENCRYPTION_KEY;
    } else {
      process.env.MCP_ENCRYPTION_KEY = originalEncryptionKey;
    }
  });

  describe.each(modelCases)("$model model", ({ model, id, payload }) => {
    test("upsert and find round-trip the complete payload without sharing caller state", async () => {
      const adapter = MariaDbOidcAdapter.factory(pool)(model);
      const callerSnapshot = structuredClone(payload);

      // oidc-provider persists configured Client metadata without a TTL.
      await adapter.upsert(
        id,
        payload,
        model === "Client" ? undefined : 120,
      );
      const found = await adapter.find(id);

      expect(found).toEqual(payload);
      expect(found).not.toBe(payload);
      expect(payload).toEqual(callerSnapshot);

      if (found?.extra !== undefined) {
        found.extra.changedByTest = true;
      }
      expect(payload).toEqual(callerSnapshot);
    });

    test("find excludes rows whose database expiry has passed even when payload expiry is future-dated", async () => {
      const adapter = MariaDbOidcAdapter.factory(pool)(model);
      const futurePayload = {
        ...payload,
        exp: 4_102_444_800,
      };

      await adapter.upsert(id, futurePayload, 120);
      await pool.execute(
        `UPDATE oidc_objects
        SET expires_at = TIMESTAMPADD(MICROSECOND, -1, UTC_TIMESTAMP(6))
        WHERE model = ?`,
        [model],
      );

      await expect(adapter.find(id)).resolves.toBeUndefined();
    });

    test("destroy removes only the addressed model and identifier", async () => {
      const adapter = MariaDbOidcAdapter.factory(pool)(model);
      const otherModel = MariaDbOidcAdapter.factory(pool)("OtherModel");

      await adapter.upsert(id, payload, 120);
      await adapter.upsert(`${id}-other-id`, { kind: model }, 120);
      await otherModel.upsert(id, { kind: "OtherModel" }, 120);

      await adapter.destroy(id);

      await expect(adapter.find(id)).resolves.toBeUndefined();
      await expect(adapter.find(`${id}-other-id`)).resolves.toEqual({
        kind: model,
      });
      await expect(otherModel.find(id)).resolves.toEqual({
        kind: "OtherModel",
      });
    });
  });

  test("stores exact domain-separated lookup hashes while no raw identifier or payload secret occurs anywhere in the row", async () => {
    const id = "session-primary-secret-A7q9";
    const grantId = "grant-secret-G5r8";
    const userCode = "user-code-secret-U4c6";
    const uid = "uid-secret-D2v7";
    const accessToken = "access-token-secret-T8m3";
    const authorizationCode = "authorization-code-secret-C9p1";
    const adapter = MariaDbOidcAdapter.factory(pool)("Session");
    const payload: AdapterPayload = {
      jti: id,
      uid,
      userCode,
      grantId,
      request: accessToken,
      nonce: authorizationCode,
      session: { uid },
      state: {
        rawAdapterId: id,
        rawToken: accessToken,
        rawCode: authorizationCode,
      },
    };

    await adapter.upsert(id, payload, 120);

    await expect(adapter.find(id)).resolves.toEqual(payload);
    const [rows] = await pool.query<RawOidcRow[]>(`
      SELECT
        model,
        HEX(id_hash) AS idHash,
        CAST(payload_json AS CHAR) AS payload,
        HEX(grant_id) AS grantHash,
        HEX(user_code_hash) AS userCodeHash,
        HEX(uid_hash) AS uidHash,
        DATE_FORMAT(consumed_at, '%Y-%m-%d %H:%i:%s.%f') AS consumedAt,
        DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s.%f') AS expiresAt
      FROM oidc_objects
    `);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      model: "Session",
      idHash:
        "191EA289EFD3D038C0B2BDE7EA5181A15ABAC5541B29834FBFB39D968038A7AF",
      grantHash:
        "4FF734730F19194B7EC7B972746C25AE94C1C75A8465B6C40C14FB5DEB4C6C39",
      userCodeHash:
        "AE4339341ECB3F5FCB02EA1B40B292F634E68CED0B2B0605AD5AA1B74B1D2643",
      uidHash:
        "C7480D6E0EDE6F4284AC145BEEBD2EE1187142432B2ECFE94E1778A79BB57EE0",
      consumedAt: null,
    });

    const completeRawRow = JSON.stringify(rows[0]);
    for (const secret of [
      id,
      grantId,
      userCode,
      uid,
      accessToken,
      authorizationCode,
    ]) {
      expect(completeRawRow).not.toContain(secret);
    }
  });

  test("consume records one database timestamp once and exposes it through find without mutating the input", async () => {
    const id = "consume-once-authorization-code";
    const payload: AdapterPayload = {
      kind: "AuthorizationCode",
      jti: id,
      accountId: "consume-account",
    };
    const callerSnapshot = structuredClone(payload);
    const adapter = MariaDbOidcAdapter.factory(pool)("AuthorizationCode");

    await adapter.upsert(id, payload, 120);
    await Promise.all([
      adapter.consume(id),
      adapter.consume(id),
      adapter.consume(id),
    ]);
    const first = await adapter.find(id);
    const [firstRows] = await pool.query<ConsumedRow[]>(
      "SELECT consumed_at AS consumedAt FROM oidc_objects",
    );

    await new Promise((resolve) => setTimeout(resolve, 10));
    await adapter.consume(id);
    const [secondRows] = await pool.query<ConsumedRow[]>(
      "SELECT consumed_at AS consumedAt FROM oidc_objects",
    );

    expect(first).toEqual({
      ...payload,
      consumed: expect.any(Number),
    });
    expect(firstRows[0]?.consumedAt).toBeInstanceOf(Date);
    expect(secondRows[0]?.consumedAt).toEqual(firstRows[0]?.consumedAt);
    expect(payload).toEqual(callerSnapshot);
  });

  test("findByUserCode uses its hash, restores the complete payload, and enforces database expiry", async () => {
    const id = "device-code-primary-id";
    const userCode = "ABCD-EFGH-user-code";
    const payload: AdapterPayload = {
      kind: "DeviceCode",
      jti: id,
      userCode,
      accountId: "device-account",
    };
    const adapter = MariaDbOidcAdapter.factory(pool)("DeviceCode");

    await adapter.upsert(id, payload, 120);

    await expect(adapter.findByUserCode(userCode)).resolves.toEqual(payload);
    await expect(
      adapter.findByUserCode("wrong-user-code"),
    ).resolves.toBeUndefined();

    await pool.query(
      "UPDATE oidc_objects SET expires_at = UTC_TIMESTAMP(6)",
    );
    await expect(adapter.findByUserCode(userCode)).resolves.toBeUndefined();
  });

  test("findByUid uses its hash, restores the complete session payload, and enforces database expiry", async () => {
    const id = "uid-session-primary-id";
    const uid = "session-secondary-uid";
    const payload: AdapterPayload = {
      kind: "Session",
      jti: id,
      uid,
      accountId: "session-account",
    };
    const adapter = MariaDbOidcAdapter.factory(pool)("Session");

    await adapter.upsert(id, payload, 120);

    await expect(adapter.findByUid(uid)).resolves.toEqual(payload);
    await expect(adapter.findByUid("wrong-uid")).resolves.toBeUndefined();

    await pool.query(
      "UPDATE oidc_objects SET expires_at = UTC_TIMESTAMP(6)",
    );
    await expect(adapter.findByUid(uid)).resolves.toBeUndefined();
  });

  test("revokeByGrantId transactionally removes every indexed model row for the grant and preserves unrelated rows", async () => {
    const grantId = "grant-wide-revocation-id";
    const accessToken = MariaDbOidcAdapter.factory(pool)("AccessToken");
    const authorizationCode =
      MariaDbOidcAdapter.factory(pool)("AuthorizationCode");
    const refreshToken = MariaDbOidcAdapter.factory(pool)("RefreshToken");

    await accessToken.upsert(
      "grant-access-token",
      { kind: "AccessToken", grantId },
      120,
    );
    await authorizationCode.upsert(
      "grant-authorization-code",
      { kind: "AuthorizationCode", grantId },
      120,
    );
    await refreshToken.upsert(
      "grant-refresh-token",
      { kind: "RefreshToken", grantId },
      120,
    );
    await refreshToken.upsert(
      "unrelated-refresh-token",
      { kind: "RefreshToken", grantId: "unrelated-grant-id" },
      120,
    );

    await accessToken.revokeByGrantId(grantId);

    await expect(accessToken.find("grant-access-token")).resolves.toBeUndefined();
    await expect(
      authorizationCode.find("grant-authorization-code"),
    ).resolves.toBeUndefined();
    await expect(
      refreshToken.find("grant-refresh-token"),
    ).resolves.toBeUndefined();
    await expect(
      refreshToken.find("unrelated-refresh-token"),
    ).resolves.toEqual({
      kind: "RefreshToken",
      grantId: "unrelated-grant-id",
    });
    const [rows] = await pool.query<CountRow[]>(
      "SELECT COUNT(*) AS count FROM oidc_objects",
    );
    expect(rows).toEqual([{ count: 1 }]);
  });

  test("a fresh Node process recovers rows without module-local state", async () => {
    const id = "restart-persistence-refresh-token";
    const payload: AdapterPayload = {
      kind: "RefreshToken",
      jti: id,
      grantId: "restart-persistence-grant",
      accountId: "restart-account",
    };

    await MariaDbOidcAdapter.factory(pool)("RefreshToken").upsert(
      id,
      payload,
      120,
    );
    const childScript = `
      import { MariaDbOidcAdapter } from "./src/auth/oidc-adapter.ts";
      import { createPool } from "./src/db/pool.ts";

      const pool = createPool({
        host: process.env.ADAPTER_TEST_DB_HOST,
        port: Number(process.env.ADAPTER_TEST_DB_PORT),
        database: process.env.ADAPTER_TEST_DB_NAME,
        user: process.env.ADAPTER_TEST_DB_USER,
        password: process.env.ADAPTER_TEST_DB_PASSWORD,
      });

      try {
        const found = await MariaDbOidcAdapter
          .factory(pool)("RefreshToken")
          .find("restart-persistence-refresh-token");
        const expected = {
          kind: "RefreshToken",
          jti: "restart-persistence-refresh-token",
          grantId: "restart-persistence-grant",
          accountId: "restart-account",
        };

        if (JSON.stringify(found) !== JSON.stringify(expected)) {
          throw new Error("restart payload mismatch");
        }
        process.stdout.write("ok");
      } finally {
        await pool.end();
      }
    `;
    const { stdout } = await execFileAsync(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "--eval", childScript],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          ADAPTER_TEST_DB_HOST: databaseHost,
          ADAPTER_TEST_DB_PORT: String(databasePort),
          ADAPTER_TEST_DB_NAME: databaseName,
          ADAPTER_TEST_DB_USER: databaseUser,
          ADAPTER_TEST_DB_PASSWORD: databasePassword,
        },
      },
    );

    expect(stdout).toBe("ok");
  });

  test("concurrent upserts leave one complete payload and matching secondary indexes", async () => {
    const id = "concurrent-upsert-session-id";
    const adapter = MariaDbOidcAdapter.factory(pool)("Session");
    const payloads: AdapterPayload[] = [
      {
        kind: "Session",
        jti: id,
        uid: "concurrent-uid-1",
        userCode: "concurrent-user-code-1",
        state: { revision: 1, marker: "complete-one" },
      },
      {
        kind: "Session",
        jti: id,
        uid: "concurrent-uid-2",
        userCode: "concurrent-user-code-2",
        state: { revision: 2, marker: "complete-two" },
      },
      {
        kind: "Session",
        jti: id,
        uid: "concurrent-uid-3",
        userCode: "concurrent-user-code-3",
        state: { revision: 3, marker: "complete-three" },
      },
    ];

    await Promise.all(
      payloads.flatMap((payload) =>
        Array.from({ length: 4 }, () => adapter.upsert(id, payload, 120)),
      ),
    );

    const found = await adapter.find(id);
    expect(payloads).toContainEqual(found);
    const winner = payloads.find((payload) => payload.uid === found?.uid);
    expect(winner).toEqual(found);
    await expect(adapter.findByUid(found?.uid ?? "")).resolves.toEqual(found);
    await expect(
      adapter.findByUserCode(found?.userCode ?? ""),
    ).resolves.toEqual(found);

    for (const payload of payloads.filter((candidate) => candidate !== winner)) {
      await expect(
        adapter.findByUid(payload.uid ?? ""),
      ).resolves.toBeUndefined();
      await expect(
        adapter.findByUserCode(payload.userCode ?? ""),
      ).resolves.toBeUndefined();
    }

    const [rows] = await pool.query<CountRow[]>(
      "SELECT COUNT(*) AS count FROM oidc_objects",
    );
    expect(rows).toEqual([{ count: 1 }]);
  });
});
