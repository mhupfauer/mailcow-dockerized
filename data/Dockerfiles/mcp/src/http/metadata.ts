import {
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import express from "express";

import { MCP_OAUTH_SCOPES } from "../auth/oidc-provider.js";

interface MetadataDependencies {
  issuer: string;
  resource: URL;
}

export function createMcpMetadataRouter({
  issuer,
  resource,
}: MetadataDependencies) {
  const canonicalIssuer = new URL(issuer).href.replace(/\/$/u, "");
  const sdkRouter = mcpAuthMetadataRouter({
    oauthMetadata: {
      issuer: canonicalIssuer,
      authorization_endpoint: new URL("/oauth/auth", canonicalIssuer).href,
      token_endpoint: new URL("/oauth/token", canonicalIssuer).href,
      registration_endpoint: new URL("/oauth/reg", canonicalIssuer).href,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...MCP_OAUTH_SCOPES],
    },
    resourceServerUrl: resource,
    scopesSupported: [...MCP_OAUTH_SCOPES],
  });
  const protectedResourcePath =
    `/.well-known/oauth-protected-resource${
      resource.pathname === "/" ? "" : resource.pathname
    }`;
  const router = express.Router();
  router.use((request, response, next) => {
    if (request.path !== protectedResourcePath) {
      next();
      return;
    }
    sdkRouter(request, response, next);
  });
  return router;
}
