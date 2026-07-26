import { describe, expect, test } from "vitest";

import { loadConfig } from "../../src/config.js";

const validEnvironment = {
  MAILCOW_HOSTNAME: "mail.example.test",
  MCP_PORT: "3000",
  MCP_DBHOST: "mysql-mailcow",
  MCP_DBNAME: "mailcow_mcp",
  MCP_DBUSER: "mailcow_mcp",
  MCP_DBPASS: "database-password",
  MCP_ENCRYPTION_KEY:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
};

describe("loadConfig", () => {
  test("parses a valid 64-character hexadecimal encryption key", () => {
    const config = loadConfig(validEnvironment);

    expect(config.encryptionKey).toEqual(
      Buffer.from(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "hex",
      ),
    );
  });

  test("rejects a 63-character encryption key", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        MCP_ENCRYPTION_KEY: "a".repeat(63),
      }),
    ).toThrow("MCP_ENCRYPTION_KEY must be 64 hexadecimal characters");
  });

  test("rejects an empty database password without exposing it", () => {
    let error: unknown;

    try {
      loadConfig({ ...validEnvironment, MCP_DBPASS: "" });
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("MCP_DBPASS must not be empty");
  });
});
