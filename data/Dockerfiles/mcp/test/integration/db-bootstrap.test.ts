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
      const schemaGrants = grants
        .flatMap((grant) => Object.values(grant))
        .filter((grant) => grant.includes(" ON `"));
      expect(schemaGrants).toEqual([
        "GRANT ALL PRIVILEGES ON `mailcow_mcp`.* TO `mailcow_mcp`@`%`",
      ]);
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
});
