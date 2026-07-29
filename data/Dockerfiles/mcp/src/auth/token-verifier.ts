import type { Provider } from "oidc-provider";

import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

import { MCP_OAUTH_SCOPES } from "./oidc-provider.js";

interface AccessTokenVerifierDependencies {
  provider: Provider;
  resource: URL;
  authorizationRepository: {
    getActive(
      accountId: string,
      clientId: string,
    ): Promise<{
      resource?: string;
      grantId?: string;
      scopes: readonly string[];
    } | null>;
  };
}

function invalidToken(): never {
  throw new InvalidTokenError("Invalid access token");
}

function hasExpectedAudience(audience: unknown, resource: URL): boolean {
  return audience === resource.href;
}

export class AccessTokenVerifier {
  constructor(private readonly dependencies: AccessTokenVerifierDependencies) {}

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const accessToken =
        await this.dependencies.provider.AccessToken.find(token);
      if (
        accessToken === undefined ||
        typeof accessToken.accountId !== "string" ||
        accessToken.accountId === "" ||
        typeof accessToken.clientId !== "string" ||
        accessToken.clientId === "" ||
        typeof accessToken.grantId !== "string" ||
        accessToken.grantId === "" ||
        typeof accessToken.scope !== "string" ||
        typeof accessToken.exp !== "number" ||
        accessToken.exp <= Date.now() / 1_000 ||
        !hasExpectedAudience(accessToken.aud, this.dependencies.resource)
      ) {
        return invalidToken();
      }

      const client = await this.dependencies.provider.Client.find(
        accessToken.clientId,
      );
      if (client === undefined) {
        return invalidToken();
      }

      const scopes = [
        ...new Set(
          accessToken.scope.split(" ").filter((scope) => scope !== ""),
        ),
      ];
      if (
        scopes.some(
          (scope) =>
            !(MCP_OAUTH_SCOPES as readonly string[]).includes(scope),
        )
      ) {
        return invalidToken();
      }
      const active =
        await this.dependencies.authorizationRepository.getActive(
          accessToken.accountId,
          accessToken.clientId,
        );
      if (
        active === null ||
        active.resource !== this.dependencies.resource.href ||
        active.grantId !== accessToken.grantId ||
        scopes.some((scope) => !active.scopes.includes(scope))
      ) {
        return invalidToken();
      }

      return {
        token,
        clientId: accessToken.clientId,
        scopes,
        expiresAt: accessToken.exp,
        resource: new URL(this.dependencies.resource),
        extra: { accountId: accessToken.accountId },
      };
    } catch {
      return invalidToken();
    }
  }
}
