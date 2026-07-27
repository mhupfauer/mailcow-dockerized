export interface AppConfig {
  hostname: string;
  issuer: URL;
  resource: URL;
  resourceMetadataUrl: URL;
  port: number;
  registrationsPerHour: number;
  loginAttempts: number;
  loginWindowSeconds: number;
  tlsTrustPath: string;
  db: {
    host: string;
    port: number;
    name: string;
    user: string;
    password: string;
  };
  encryptionKey: Buffer;
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
    throw new Error("MCP_PORT must be an integer between 1 and 65535");
  }

  const port = Number(value);
  if (port < 1 || port > 65_535) {
    throw new Error("MCP_PORT must be an integer between 1 and 65535");
  }

  return port;
}

function parseDatabasePort(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("MCP_DBPORT must be an integer between 1 and 65535");
  }

  const port = Number(value);
  if (port < 1 || port > 65_535) {
    throw new Error("MCP_DBPORT must be an integer between 1 and 65535");
  }

  return port;
}

function positiveInteger(
  value: string | undefined,
  fallback: number,
  variableName: string,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`${variableName} must be a positive integer`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${variableName} must be a positive integer`);
  }
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const hostname = required(env, "MAILCOW_HOSTNAME");
  const encryptionKey = required(env, "MCP_ENCRYPTION_KEY");
  const databasePassword = required(env, "MCP_DBPASS");

  if (!/^[0-9a-fA-F]{64}$/.test(encryptionKey)) {
    throw new Error("MCP_ENCRYPTION_KEY must be 64 hexadecimal characters");
  }

  if (!/^[0-9a-fA-F]{64}$/.test(databasePassword)) {
    throw new Error("MCP_DBPASS must be 64 hexadecimal characters");
  }

  const issuer = new URL(`https://${hostname}`);

  return {
    hostname,
    issuer,
    resource: new URL("/mcp", issuer),
    resourceMetadataUrl: new URL(
      "/.well-known/oauth-protected-resource/mcp",
      issuer,
    ),
    port: parsePort(required(env, "MCP_PORT")),
    registrationsPerHour: positiveInteger(
      env.MCP_REGISTRATIONS_PER_HOUR,
      10,
      "MCP_REGISTRATIONS_PER_HOUR",
    ),
    loginAttempts: positiveInteger(
      env.MCP_LOGIN_ATTEMPTS,
      5,
      "MCP_LOGIN_ATTEMPTS",
    ),
    loginWindowSeconds: positiveInteger(
      env.MCP_LOGIN_WINDOW_SECONDS,
      900,
      "MCP_LOGIN_WINDOW_SECONDS",
    ),
    tlsTrustPath:
      env.MCP_TLS_TRUST_PATH === undefined
        ? "/etc/ssl/mail/cert.pem"
        : required(env, "MCP_TLS_TRUST_PATH"),
    db: {
      host: required(env, "MCP_DBHOST"),
      port: parseDatabasePort(env.MCP_DBPORT ?? "3306"),
      name: required(env, "MCP_DBNAME"),
      user: required(env, "MCP_DBUSER"),
      password: databasePassword,
    },
    encryptionKey: Buffer.from(encryptionKey, "hex"),
  };
}
