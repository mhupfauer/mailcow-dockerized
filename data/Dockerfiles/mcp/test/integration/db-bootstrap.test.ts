import { createConnection } from "mysql2/promise";
import { GenericContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { initializeDatabase } from "../../src/db/init.js";
import { createPool } from "../../src/db/pool.js";
import { runMigrations } from "../../src/db/migrations.js";

const rootPassword = "root-password-for-disposable-test";
const databasePassword = "database-password-for-disposable-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const migrationLockName = "mailcow_mcp_migrations";

test("rejects database identifiers before connecting", async () => {
  await expect(
    initializeDatabase({
      host: "127.0.0.1",
      port: 3306,
      rootPassword,
      databaseName: "mailcow_mcp; DROP DATABASE mysql",
      databaseUser,
      databasePassword,
    }),
  ).rejects.toThrow("MCP_DBNAME must be a valid MariaDB identifier");
});

describe("MCP database bootstrap", () => {
  let container: Awaited<ReturnType<GenericContainer["start"]>>;

  beforeAll(async () => {
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();
  }, 120_000);

  afterAll(async () => {
    await container?.stop();
  });

  test("creates an idempotent dedicated schema, user, and initial migration", async () => {
    const host = container.getHost();
    const port = container.getMappedPort(3306);
    const bootstrapConfig = {
      host,
      port,
      rootPassword,
      databaseName,
      databaseUser,
      databasePassword,
    };

    await initializeDatabase(bootstrapConfig);
    await initializeDatabase(bootstrapConfig);

    const rootConnection = await createConnection({
      host,
      port,
      user: "root",
      password: rootPassword,
    });

    try {
      const [schemas] = await rootConnection.query<{ SCHEMA_NAME: string }[]>(
        "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'mailcow_mcp'",
      );
      const [grants] = await rootConnection.query<Record<string, string>[]>(
        "SHOW GRANTS FOR 'mailcow_mcp'@'%'",
      );

      expect(schemas).toEqual([{ SCHEMA_NAME: "mailcow_mcp" }]);
      const grantStrings = grants.flatMap((grant) => Object.values(grant));

      expect(grantStrings).toHaveLength(2);
      expect(grantStrings).toContain(
        "GRANT ALL PRIVILEGES ON `mailcow_mcp`.* TO `mailcow_mcp`@`%`",
      );
      expect(grantStrings).toContainEqual(
        expect.stringMatching(
          /^GRANT USAGE ON \*\.\* TO `mailcow_mcp`@`%` IDENTIFIED BY PASSWORD /,
        ),
      );
      expect(
        grantStrings.every(
          (grant) =>
            grant.startsWith("GRANT USAGE ON *.* ") ||
            grant ===
              "GRANT ALL PRIVILEGES ON `mailcow_mcp`.* TO `mailcow_mcp`@`%`",
        ),
      ).toBe(true);
    } finally {
      await rootConnection.end();
    }

    const pool = createPool({
      host,
      port,
      database: databaseName,
      user: databaseUser,
      password: databasePassword,
    });

    try {
      await runMigrations(pool);
      await runMigrations(pool);

      const [migrations] = await pool.query<{ version: number }[]>(
        "SELECT version FROM schema_migrations",
      );

      expect(migrations).toEqual([{ version: 1 }]);
    } finally {
      await pool.end();
    }
  }, 120_000);

  test("serializes concurrent migration runners behind the MariaDB advisory lock", async () => {
    const host = container.getHost();
    const port = container.getMappedPort(3306);
    const concurrentDatabaseName = "mailcow_mcp_concurrent";
    const concurrentDatabaseUser = "mailcow_mcp_concurrent";

    await initializeDatabase({
      host,
      port,
      rootPassword,
      databaseName: concurrentDatabaseName,
      databaseUser: concurrentDatabaseUser,
      databasePassword,
    });

    const lockConnection = await createConnection({
      host,
      port,
      user: "root",
      password: rootPassword,
    });
    const firstPool = createPool({
      host,
      port,
      database: concurrentDatabaseName,
      user: concurrentDatabaseUser,
      password: databasePassword,
    });
    const secondPool = createPool({
      host,
      port,
      database: concurrentDatabaseName,
      user: concurrentDatabaseUser,
      password: databasePassword,
    });

    try {
      const [lockRows] = await lockConnection.query<{ acquired: number }[]>(
        "SELECT GET_LOCK(?, 0) AS acquired",
        [migrationLockName],
      );
      expect(lockRows).toEqual([{ acquired: 1 }]);

      let completed = false;
      const concurrentRuns = Promise.all([
        runMigrations(firstPool),
        runMigrations(secondPool),
      ]).then(() => {
        completed = true;
      });

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(completed).toBe(false);

      await lockConnection.query("SELECT RELEASE_LOCK(?)", [migrationLockName]);
      await concurrentRuns;

      const [migrations] = await firstPool.query<{ version: number }[]>(
        "SELECT version FROM schema_migrations",
      );
      expect(migrations).toEqual([{ version: 1 }]);
    } finally {
      await lockConnection.query("SELECT RELEASE_LOCK(?)", [migrationLockName]);
      await Promise.all([firstPool.end(), secondPool.end()]);
      await lockConnection.end();
    }
  }, 120_000);
});
