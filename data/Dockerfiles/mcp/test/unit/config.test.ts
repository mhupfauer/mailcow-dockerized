import { describe, expect, test } from "vitest";

import { loadConfig } from "../../src/config.js";

const validEnvironment = {
  MAILCOW_HOSTNAME: "mail.example.test",
  MCP_PORT: "3000",
  MCP_DBHOST: "mysql-mailcow",
  MCP_DBNAME: "mailcow_mcp",
  MCP_DBUSER: "mailcow_mcp",
  MCP_DBPASS:
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  MCP_ENCRYPTION_KEY:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
};

describe("loadConfig", () => {
  test("parses a valid 64-character hexadecimal encryption key", () => {
    const config = loadConfig({
      ...validEnvironment,
      MCP_DBPORT: "3307",
      MCP_REGISTRATIONS_PER_HOUR: "12",
      MCP_LOGIN_ATTEMPTS: "7",
      MCP_LOGIN_WINDOW_SECONDS: "1200",
      MCP_TLS_TRUST_PATH: "/test/mailcow-cert.pem",
    });

    expect(config.encryptionKey).toEqual(
      Buffer.from(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "hex",
      ),
    );
    expect(config.db.password).toBe(
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    );
    expect(config.db.port).toBe(3307);
    expect(config.registrationsPerHour).toBe(12);
    expect(config.loginAttempts).toBe(7);
    expect(config.loginWindowSeconds).toBe(1200);
    expect(config.tlsTrustPath).toBe("/test/mailcow-cert.pem");
    expect(config.resource.href).toBe("https://mail.example.test/mcp");
    expect(config.resourceMetadataUrl.href).toBe(
      "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
    );
  });

  test("uses the mounted mailcow certificate and reviewed login limits by default", () => {
    const config = loadConfig(validEnvironment);

    expect(config.loginAttempts).toBe(5);
    expect(config.loginWindowSeconds).toBe(900);
    expect(config.tlsTrustPath).toBe("/etc/ssl/mail/cert.pem");
  });

  test("rejects a 63-character encryption key", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        MCP_ENCRYPTION_KEY: "a".repeat(63),
      }),
    ).toThrow("MCP_ENCRYPTION_KEY must be 64 hexadecimal characters");
  });

  test("rejects a database password that is not 64 hexadecimal characters", () => {
    expect(() =>
      loadConfig({
        ...validEnvironment,
        MCP_DBPASS: "database-password",
      }),
    ).toThrow("MCP_DBPASS must be 64 hexadecimal characters");
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
