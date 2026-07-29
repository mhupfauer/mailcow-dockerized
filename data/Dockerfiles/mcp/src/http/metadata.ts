import {
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";

import { MCP_OAUTH_SCOPES } from "../auth/oidc-provider.js";

interface MetadataDependencies {
  issuer: URL;
  resource: URL;
}

export function createMcpMetadataRouter({
  issuer,
  resource,
}: MetadataDependencies) {
  return mcpAuthMetadataRouter({
    oauthMetadata: {
      issuer: issuer.href,
      authorization_endpoint: new URL("/oauth/auth", issuer).href,
      token_endpoint: new URL("/oauth/token", issuer).href,
      registration_endpoint: new URL("/oauth/reg", issuer).href,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...MCP_OAUTH_SCOPES],
    },
    resourceServerUrl: resource,
    scopesSupported: [...MCP_OAUTH_SCOPES],
  });
}
