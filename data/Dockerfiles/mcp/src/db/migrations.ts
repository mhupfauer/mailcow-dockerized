import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import type { Pool, RowDataPacket } from "mysql2/promise";
import { createPool } from "./pool.js";

interface Migration {
  version: number;
  filename: string;
}

const migrations: Migration[] = [{ version: 1, filename: "001_initial.sql" }];
const migrationLockName = "mailcow_mcp_migrations";

async function loadMigration(filename: string): Promise<string> {
  return readFile(new URL(`./migrations/${filename}`, import.meta.url), "utf8");
}

export async function runMigrations(pool: Pool): Promise<void> {
  const connection = await pool.getConnection();
  let lockAcquired = false;

  try {
    const [lockRows] = await connection.query<
      (RowDataPacket & { acquired: number | null })[]
    >("SELECT GET_LOCK(?, 60) AS acquired", [migrationLockName]);

    if (lockRows[0]?.acquired !== 1) {
      throw new Error("could not acquire the MCP database migration lock");
    }

    lockAcquired = true;

    const [tables] = await connection.query<RowDataPacket[]>(
      "SHOW TABLES LIKE 'schema_migrations'",
    );
    const applied = new Set<number>();

    if (tables.length > 0) {
      const [rows] = await connection.query<(RowDataPacket & { version: number })[]>(
        "SELECT version FROM schema_migrations",
      );
      for (const row of rows) {
        applied.add(row.version);
      }
    }

    for (const migration of migrations) {
      if (applied.has(migration.version)) {
        continue;
      }

      const statements = (await loadMigration(migration.filename))
        .split(";")
        .map((statement) => statement.trim())
        .filter((statement) => statement !== "");

      for (const statement of statements) {
        await connection.query(statement);
      }

      // MariaDB DDL auto-commits. Migrations must therefore be replay-safe if
      // a process stops after DDL but before this version record; 001 uses
      // CREATE TABLE IF NOT EXISTS. The lock prevents concurrent replays.
      await connection.beginTransaction();
      try {
        await connection.execute(
          "INSERT INTO schema_migrations (version) VALUES (?)",
          [migration.version],
        );
        await connection.commit();
      } catch (error) {
        await connection.rollback();
        throw error;
      }
    }
  } finally {
    if (lockAcquired) {
      await connection.query("SELECT RELEASE_LOCK(?)", [migrationLockName]);
    }
    connection.release();
  }
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];

  if (value === undefined || value.trim() === "") {
    throw new Error(`${name} must not be empty`);
  }

  return value;
}

function parsePort(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("MCP_DBPORT must be an integer between 1 and 65535");
  }

  const port = Number(value);
  if (port < 1 || port > 65_535) {
    throw new Error("MCP_DBPORT must be an integer between 1 and 65535");
  }

  return port;
}

async function runMigrationsFromEnvironment(
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const pool = createPool({
    host: required(env, "MCP_DBHOST"),
    port: parsePort(env.MCP_DBPORT ?? "3306"),
    database: required(env, "MCP_DBNAME"),
    user: required(env, "MCP_DBUSER"),
    password: required(env, "MCP_DBPASS"),
  });

  try {
    await runMigrations(pool);
  } finally {
    await pool.end();
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runMigrationsFromEnvironment(process.env).catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
