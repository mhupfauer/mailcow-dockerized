import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

import { MCP_OAUTH_SCOPES } from "../auth/oidc-provider.js";

export type Scope = (typeof MCP_OAUTH_SCOPES)[number];

export interface AccountContext {
  accountId: string;
  clientId: string;
  scopes: ReadonlySet<Scope>;
  tokenExpiresAt: number;
}

export function requireAccountContext(
  authInfo: AuthInfo,
): AccountContext {
  const accountId = authInfo.extra?.accountId;
  const scopes = new Set<Scope>();
  for (const scope of authInfo.scopes) {
    if (!(MCP_OAUTH_SCOPES as readonly string[]).includes(scope)) {
      throw new Error("invalid authenticated account context");
    }
    scopes.add(scope as Scope);
  }
  if (
    typeof accountId !== "string" ||
    accountId === "" ||
    authInfo.clientId === "" ||
    typeof authInfo.expiresAt !== "number" ||
    !Number.isFinite(authInfo.expiresAt) ||
    scopes.size === 0
  ) {
    throw new Error("invalid authenticated account context");
  }

  return {
    accountId,
    clientId: authInfo.clientId,
    scopes,
    tokenExpiresAt: authInfo.expiresAt,
  };
}
