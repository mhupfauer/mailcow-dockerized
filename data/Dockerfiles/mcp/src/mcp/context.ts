import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export interface AccountContext {
  accountId: string;
  clientId: string;
}

export function requireAccountContext(
  authInfo: AuthInfo,
  requiredScope: string,
): AccountContext {
  const accountId = authInfo.extra?.accountId;
  if (
    typeof accountId !== "string" ||
    accountId === "" ||
    !authInfo.scopes.includes(requiredScope)
  ) {
    throw new Error("invalid authenticated account context");
  }

  return { accountId, clientId: authInfo.clientId };
}
