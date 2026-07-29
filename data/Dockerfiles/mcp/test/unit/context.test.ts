import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { describe, expect, test } from "vitest";

import {
  requireAccountContext,
  type Scope,
} from "../../src/mcp/context.js";

function authInfo(scopes: string[] = ["mail.send"]): AuthInfo {
  return {
    token: "opaque-token",
    clientId: "client-one",
    scopes,
    expiresAt: 1_900_000_000,
    extra: { accountId: "123e4567-e89b-42d3-a456-426614174000" },
  };
}

describe("requireAccountContext", () => {
  test("derives the fixed cross-phase account context from current authentication", () => {
    const context = requireAccountContext(
      authInfo(["mail.organize", "mail.send"]),
    );

    expect(context).toEqual({
      accountId: "123e4567-e89b-42d3-a456-426614174000",
      clientId: "client-one",
      scopes: new Set<Scope>(["mail.organize", "mail.send"]),
      tokenExpiresAt: 1_900_000_000,
    });
  });

  test.each([
    ["missing account", { ...authInfo(), extra: {} }],
    ["empty client", { ...authInfo(), clientId: "" }],
    ["missing expiry", { ...authInfo(), expiresAt: undefined }],
    ["no usable scope", authInfo([])],
    ["unknown scope", authInfo(["openid"])],
  ])("rejects %s authentication state", (_caseName, value) => {
    expect(() => requireAccountContext(value)).toThrow(
      "invalid authenticated account context",
    );
  });
});
