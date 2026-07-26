import { rm, writeFile } from "node:fs/promises";
import { GenericContainer } from "testcontainers";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import { initializeDatabase } from "../../src/db/init.js";
import { runMigrations } from "../../src/db/migrations.js";
import { createPool } from "../../src/db/pool.js";
import { expectedIndexes } from "../fixtures/expected-indexes.js";

const rootPassword = "root-password-for-oauth-schema-test";
const databasePassword = "database-password-for-oauth-schema-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";

interface ColumnMetadata {
  tableName: string;
  columnName: string;
  dataType: string;
  columnType: string;
  nullable: "YES" | "NO";
  datetimePrecision: number | null;
}

interface IndexRow {
  TABLE_NAME: string;
  INDEX_NAME: string;
  NON_UNIQUE: number;
  SEQ_IN_INDEX: number;
  COLUMN_NAME: string;
}

interface ForeignKeyRow {
  TABLE_NAME: string;
  CONSTRAINT_NAME: string;
  COLUMN_NAME: string;
  REFERENCED_TABLE_NAME: string;
  REFERENCED_COLUMN_NAME: string;
  DELETE_RULE: string;
}

interface JsonCheckRow {
  tableName: string;
  checkClause: string;
}

const expectedColumns: readonly ColumnMetadata[] = [
  { tableName: "accounts", columnName: "created_at", dataType: "datetime", columnType: "datetime(6)", nullable: "NO", datetimePrecision: 6 },
  { tableName: "accounts", columnName: "credential_envelope", dataType: "text", columnType: "text", nullable: "NO", datetimePrecision: null },
  { tableName: "accounts", columnName: "credential_version", dataType: "tinyint", columnType: "tinyint(3) unsigned", nullable: "NO", datetimePrecision: null },
  { tableName: "accounts", columnName: "id", dataType: "binary", columnType: "binary(16)", nullable: "NO", datetimePrecision: null },
  { tableName: "accounts", columnName: "mailbox_normalized", dataType: "varchar", columnType: "varchar(254)", nullable: "NO", datetimePrecision: null },
  { tableName: "accounts", columnName: "revoked_at", dataType: "datetime", columnType: "datetime(6)", nullable: "YES", datetimePrecision: 6 },
  { tableName: "accounts", columnName: "updated_at", dataType: "datetime", columnType: "datetime(6)", nullable: "NO", datetimePrecision: 6 },
  { tableName: "audit_events", columnName: "account_id", dataType: "binary", columnType: "binary(16)", nullable: "YES", datetimePrecision: null },
  { tableName: "audit_events", columnName: "action", dataType: "varchar", columnType: "varchar(64)", nullable: "NO", datetimePrecision: null },
  { tableName: "audit_events", columnName: "count_value", dataType: "int", columnType: "int(10) unsigned", nullable: "YES", datetimePrecision: null },
  { tableName: "audit_events", columnName: "created_at", dataType: "datetime", columnType: "datetime(6)", nullable: "NO", datetimePrecision: 6 },
  { tableName: "audit_events", columnName: "id", dataType: "bigint", columnType: "bigint(20) unsigned", nullable: "NO", datetimePrecision: null },
  { tableName: "audit_events", columnName: "object_id", dataType: "varbinary", columnType: "varbinary(32)", nullable: "YES", datetimePrecision: null },
  { tableName: "audit_events", columnName: "outcome", dataType: "varchar", columnType: "varchar(32)", nullable: "NO", datetimePrecision: null },
  { tableName: "consents", columnName: "account_id", dataType: "binary", columnType: "binary(16)", nullable: "NO", datetimePrecision: null },
  { tableName: "consents", columnName: "client_id", dataType: "varchar", columnType: "varchar(255)", nullable: "NO", datetimePrecision: null },
  { tableName: "consents", columnName: "created_at", dataType: "datetime", columnType: "datetime(6)", nullable: "NO", datetimePrecision: 6 },
  { tableName: "consents", columnName: "revoked_at", dataType: "datetime", columnType: "datetime(6)", nullable: "YES", datetimePrecision: 6 },
  { tableName: "consents", columnName: "scopes", dataType: "longtext", columnType: "longtext", nullable: "NO", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "consumed_at", dataType: "datetime", columnType: "datetime(6)", nullable: "YES", datetimePrecision: 6 },
  { tableName: "oidc_objects", columnName: "expires_at", dataType: "datetime", columnType: "datetime(6)", nullable: "NO", datetimePrecision: 6 },
  { tableName: "oidc_objects", columnName: "grant_id", dataType: "varbinary", columnType: "varbinary(32)", nullable: "YES", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "id_hash", dataType: "varbinary", columnType: "varbinary(32)", nullable: "NO", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "model", dataType: "varchar", columnType: "varchar(64)", nullable: "NO", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "payload_json", dataType: "longtext", columnType: "longtext", nullable: "NO", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "uid_hash", dataType: "varbinary", columnType: "varbinary(32)", nullable: "YES", datetimePrecision: null },
  { tableName: "oidc_objects", columnName: "user_code_hash", dataType: "varbinary", columnType: "varbinary(32)", nullable: "YES", datetimePrecision: null },
];

const expectedForeignKeys: readonly ForeignKeyRow[] = [
  {
    TABLE_NAME: "audit_events",
    CONSTRAINT_NAME: "fk_audit_events_account",
    COLUMN_NAME: "account_id",
    REFERENCED_TABLE_NAME: "accounts",
    REFERENCED_COLUMN_NAME: "id",
    DELETE_RULE: "SET NULL",
  },
  {
    TABLE_NAME: "consents",
    CONSTRAINT_NAME: "fk_consents_account",
    COLUMN_NAME: "account_id",
    REFERENCED_TABLE_NAME: "accounts",
    REFERENCED_COLUMN_NAME: "id",
    DELETE_RULE: "CASCADE",
  },
];

describe("OAuth persistence schema", () => {
  let container: Awaited<ReturnType<GenericContainer["start"]>>;
  const duplicateMigrationUrl = new URL(
    "../../src/db/migrations/002_duplicate.sql",
    import.meta.url,
  );

  beforeAll(async () => {
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();
  }, 120_000);

  afterAll(async () => {
    await container?.stop();
  });

  afterEach(async () => {
    await rm(duplicateMigrationUrl, { force: true });
  });

  test("creates and replays the OAuth tables with exact lookup indexes and explicit account foreign keys", async () => {
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

      // MariaDB DDL auto-commits, so a process can stop after 002's DDL but
      // before its bookkeeping insert. Re-running must be safe in that state.
      await pool.query("DELETE FROM schema_migrations WHERE version = 2");
      await runMigrations(pool);

      const [migrations] = await pool.query<{ version: number }[]>(
        "SELECT version FROM schema_migrations ORDER BY version",
      );
      expect(migrations).toEqual([{ version: 1 }, { version: 2 }]);

      const [columns] = await pool.query<ColumnMetadata[]>(`
        SELECT
          TABLE_NAME AS tableName,
          COLUMN_NAME AS columnName,
          DATA_TYPE AS dataType,
          COLUMN_TYPE AS columnType,
          IS_NULLABLE AS nullable,
          DATETIME_PRECISION AS datetimePrecision
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME IN ('oidc_objects', 'accounts', 'consents', 'audit_events')
        ORDER BY TABLE_NAME, COLUMN_NAME
      `);

      expect(columns).toEqual(expectedColumns);
      expect(
        columns.some(({ columnName }) =>
          [
            "password",
            "app_password",
            "credential_plaintext",
            "access_token",
            "refresh_token",
            "token",
          ].includes(columnName),
        ),
      ).toBe(false);

      const [indexRows] = await pool.query<IndexRow[]>(`
        SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME IN ('oidc_objects', 'accounts', 'consents', 'audit_events')
        ORDER BY TABLE_NAME, (INDEX_NAME = 'PRIMARY') DESC, INDEX_NAME, SEQ_IN_INDEX
      `);
      const indexes = new Map<string, { tableName: string; indexName: string; nonUnique: 0 | 1; columns: string[] }>();

      for (const row of indexRows) {
        const key = `${row.TABLE_NAME}:${row.INDEX_NAME}`;
        const index = indexes.get(key) ?? {
          tableName: row.TABLE_NAME,
          indexName: row.INDEX_NAME,
          nonUnique: row.NON_UNIQUE as 0 | 1,
          columns: [],
        };
        index.columns.push(row.COLUMN_NAME);
        indexes.set(key, index);
      }

      expect([...indexes.values()]).toEqual(expectedIndexes);

      const [foreignKeys] = await pool.query<ForeignKeyRow[]>(`
        SELECT
          kcu.TABLE_NAME,
          kcu.CONSTRAINT_NAME,
          kcu.COLUMN_NAME,
          kcu.REFERENCED_TABLE_NAME,
          kcu.REFERENCED_COLUMN_NAME,
          rc.DELETE_RULE
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS kcu
        INNER JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS AS rc
          ON rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA
          AND rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
        WHERE kcu.CONSTRAINT_SCHEMA = DATABASE()
          AND kcu.TABLE_NAME IN ('consents', 'audit_events')
          AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
        ORDER BY kcu.TABLE_NAME, kcu.CONSTRAINT_NAME, kcu.ORDINAL_POSITION
      `);

      expect(foreignKeys).toEqual(expectedForeignKeys);

      const [jsonChecks] = await pool.query<JsonCheckRow[]>(`
        SELECT
          tc.TABLE_NAME AS tableName,
          cc.CHECK_CLAUSE AS checkClause
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS AS tc
        INNER JOIN INFORMATION_SCHEMA.CHECK_CONSTRAINTS AS cc
          ON cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
          AND cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
        WHERE tc.CONSTRAINT_SCHEMA = DATABASE()
          AND tc.CONSTRAINT_TYPE = 'CHECK'
          AND tc.TABLE_NAME IN ('oidc_objects', 'consents')
        ORDER BY tc.TABLE_NAME, tc.CONSTRAINT_NAME
      `);

      expect(jsonChecks).toEqual([
        { tableName: "consents", checkClause: "json_valid(`scopes`)" },
        { tableName: "oidc_objects", checkClause: "json_valid(`payload_json`)" },
      ]);
    } finally {
      await pool.end();
    }
  }, 120_000);

  test("rejects duplicate migration versions before running any migration DDL", async () => {
    await writeFile(duplicateMigrationUrl, "SELECT 1;\n", "utf8");

    const host = container.getHost();
    const port = container.getMappedPort(3306);
    const duplicateDatabaseName = "mailcow_mcp_duplicate";
    const duplicateDatabaseUser = "mailcow_mcp_duplicate";

    await initializeDatabase({
      host,
      port,
      rootPassword,
      databaseName: duplicateDatabaseName,
      databaseUser: duplicateDatabaseUser,
      databasePassword,
    });

    const pool = createPool({
      host,
      port,
      database: duplicateDatabaseName,
      user: duplicateDatabaseUser,
      password: databasePassword,
    });

    try {
      await expect(runMigrations(pool)).rejects.toThrow(
        "duplicate MCP database migration version: 2",
      );

      const [tables] = await pool.query<Record<string, string>[]>("SHOW TABLES");
      expect(tables).toEqual([]);
    } finally {
      await pool.end();
    }
  }, 120_000);

});
