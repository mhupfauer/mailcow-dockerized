import { createConnection } from "mysql2/promise";
import { pathToFileURL } from "node:url";

const identifierPattern = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

export interface DatabaseBootstrapConfig {
  host: string;
  port: number;
  rootPassword: string;
  databaseName: string;
  databaseUser: string;
  databasePassword: string;
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

function quoteIdentifier(value: string, variableName: string): string {
  if (!identifierPattern.test(value)) {
    throw new Error(`${variableName} must be a valid MariaDB identifier`);
  }

  return `\`${value}\``;
}

export async function initializeDatabase(
  config: DatabaseBootstrapConfig,
): Promise<void> {
  const databaseName = quoteIdentifier(config.databaseName, "MCP_DBNAME");
  const databaseUser = quoteIdentifier(config.databaseUser, "MCP_DBUSER");
  const connection = await createConnection({
    host: config.host,
    port: config.port,
    user: "root",
    password: config.rootPassword,
  });

  try {
    await connection.query(`CREATE DATABASE IF NOT EXISTS ${databaseName}`);
    await connection.query(
      `CREATE USER IF NOT EXISTS ${databaseUser}@'%' IDENTIFIED BY ?`,
      [config.databasePassword],
    );
    await connection.query(
      `ALTER USER ${databaseUser}@'%' IDENTIFIED BY ?`,
      [config.databasePassword],
    );
    await connection.query(
      `GRANT ALL PRIVILEGES ON ${databaseName}.* TO ${databaseUser}@'%'`,
    );
  } finally {
    await connection.end();
  }
}

function loadBootstrapConfig(env: NodeJS.ProcessEnv): DatabaseBootstrapConfig {
  return {
    host: required(env, "MCP_DBHOST"),
    port: parsePort(env.MCP_DBPORT ?? "3306"),
    rootPassword: required(env, "DBROOT"),
    databaseName: required(env, "MCP_DBNAME"),
    databaseUser: required(env, "MCP_DBUSER"),
    databasePassword: required(env, "MCP_DBPASS"),
  };
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  initializeDatabase(loadBootstrapConfig(process.env)).catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
