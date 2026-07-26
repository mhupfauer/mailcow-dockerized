export interface AppConfig {
  hostname: string;
  issuer: URL;
  resource: URL;
  port: number;
  db: { host: string; name: string; user: string; password: string };
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

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const hostname = required(env, "MAILCOW_HOSTNAME");
  const encryptionKey = required(env, "MCP_ENCRYPTION_KEY");

  if (!/^[0-9a-fA-F]{64}$/.test(encryptionKey)) {
    throw new Error("MCP_ENCRYPTION_KEY must be 64 hexadecimal characters");
  }

  const issuer = new URL(`https://${hostname}`);

  return {
    hostname,
    issuer,
    resource: new URL("/mcp", issuer),
    port: parsePort(required(env, "MCP_PORT")),
    db: {
      host: required(env, "MCP_DBHOST"),
      name: required(env, "MCP_DBNAME"),
      user: required(env, "MCP_DBUSER"),
      password: required(env, "MCP_DBPASS"),
    },
    encryptionKey: Buffer.from(encryptionKey, "hex"),
  };
}
