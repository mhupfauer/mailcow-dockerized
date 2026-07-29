import { createHmac } from "node:crypto";

import Provider, {
  errors,
  type Configuration,
  type JWK,
} from "oidc-provider";
import type { Pool } from "mysql2/promise";

import { MariaDbOidcAdapter } from "./oidc-adapter.js";
import { loadOrCreateSigningJwk } from "./signing-keys.js";

export const MCP_OAUTH_SCOPES = [
  "mail.read",
  "mail.send",
  "mail.organize",
] as const;

export const DEFAULT_OAUTH_REDIRECT_URIS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
] as const;

const allowedGrantTypes = ["authorization_code", "refresh_token"] as const;
const allowedRegistrationMetadata = new Set([
  "redirect_uris",
  "grant_types",
  "response_types",
  "token_endpoint_auth_method",
]);
const scopeString = MCP_OAUTH_SCOPES.join(" ");
const registrationPath = "/oauth/reg";

interface CreateOidcProviderDependencies {
  pool: Pool;
  issuer: URL;
  resource: URL;
  encryptionKey: Uint8Array;
  env?: NodeJS.ProcessEnv;
  allowedRedirectUris?: readonly string[];
  allowLoopbackRedirects?: boolean;
  protocolGrantRevoker?: ProtocolGrantRevoker;
}

export interface ProtocolGrantRevocationLease {
  sessionIds: readonly string[];
  release(): void;
}

export interface ProtocolGrantRevoker {
  prepare(
    accountId: string,
    clientId: string,
    resource: string,
    grantId: string,
  ): Promise<ProtocolGrantRevocationLease>;
}

interface OidcProviderPolicy {
  allowedRedirectUris: readonly string[];
  allowLoopbackRedirects: boolean;
}

interface DynamicClientMetadata {
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  [key: string]: unknown;
}

function invalidMetadata(description: string): never {
  throw new Error(description);
}

function loadProviderPolicy(env: NodeJS.ProcessEnv): OidcProviderPolicy {
  const configuredRedirects = env.MCP_OAUTH_ALLOWED_REDIRECT_URIS;
  const allowedRedirectUris =
    configuredRedirects === undefined
      ? DEFAULT_OAUTH_REDIRECT_URIS
      : configuredRedirects
          .split(",")
          .map((value) => value.trim())
          .filter((value) => value !== "");
  if (allowedRedirectUris.length === 0) {
    throw new Error(
      "MCP_OAUTH_ALLOWED_REDIRECT_URIS must contain an HTTPS URI",
    );
  }

  const loopbackValue = env.MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS ?? "1";
  if (loopbackValue !== "0" && loopbackValue !== "1") {
    throw new Error(
      "MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS must be 0 or 1",
    );
  }

  return {
    allowedRedirectUris,
    allowLoopbackRedirects: loopbackValue === "1",
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasValidExplicitPort(uri: string, parsed: URL): boolean {
  const authority = uri.slice("http://".length).split(/[/?#]/u, 1)[0];
  const match =
    parsed.hostname === "[::1]"
      ? /^\[::1\]:(\d{1,5})$/u.exec(authority)
      : /^(?:127\.0\.0\.1|localhost):(\d{1,5})$/u.exec(authority);
  if (match === null) {
    return false;
  }

  const port = Number(match[1]);
  return port >= 1 && port <= 65_535;
}

function validateRedirectUri(
  redirectUri: string,
  allowedRedirectUris: ReadonlySet<string>,
  allowLoopback: boolean,
): void {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    invalidMetadata("redirect_uris must contain valid absolute URIs");
  }

  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    redirectUri.includes("#")
  ) {
    invalidMetadata(
      "redirect_uris must not contain credentials or fragments",
    );
  }

  if (allowedRedirectUris.has(redirectUri)) {
    if (parsed.protocol !== "https:") {
      invalidMetadata("configured redirect URIs must use HTTPS");
    }
    return;
  }

  const loopbackHosts = new Set(["127.0.0.1", "[::1]", "localhost"]);
  if (
    allowLoopback &&
    parsed.protocol === "http:" &&
    loopbackHosts.has(parsed.hostname) &&
    hasValidExplicitPort(redirectUri, parsed)
  ) {
    return;
  }

  invalidMetadata("redirect URI is not approved");
}

function stringArray(
  metadata: Record<string, unknown>,
  property: string,
): string[] | undefined {
  const value = metadata[property];
  if (value === undefined) {
    return undefined;
  }
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((entry) => typeof entry === "string" && entry !== "")
  ) {
    invalidMetadata(`${property} must be a non-empty string array`);
  }
  return value as string[];
}

export function validateDynamicClient(
  metadata: unknown,
  allowedRedirectUris: ReadonlySet<string>,
  allowLoopback: boolean,
): void {
  if (!isPlainObject(metadata)) {
    invalidMetadata("registration metadata must be a JSON object");
  }
  const unsupportedProperty = Object.keys(metadata).find(
    (property) => !allowedRegistrationMetadata.has(property),
  );
  if (unsupportedProperty !== undefined) {
    invalidMetadata(`${unsupportedProperty} is not approved`);
  }

  const redirectUris = stringArray(metadata, "redirect_uris");
  if (redirectUris === undefined) {
    invalidMetadata("redirect_uris is required");
  }
  for (const redirectUri of redirectUris) {
    validateRedirectUri(
      redirectUri,
      allowedRedirectUris,
      allowLoopback,
    );
  }

  const grants = stringArray(metadata, "grant_types") ?? [
    "authorization_code",
  ];
  if (
    !grants.includes("authorization_code") ||
    grants.some(
      (grant) =>
        !(allowedGrantTypes as readonly string[]).includes(grant),
    )
  ) {
    invalidMetadata("grant_types is not approved");
  }

  const responseTypes = stringArray(metadata, "response_types") ?? ["code"];
  if (
    responseTypes.length !== 1 ||
    responseTypes[0] !== "code"
  ) {
    invalidMetadata("response_types must contain only code");
  }

  const authMethod = metadata.token_endpoint_auth_method ?? "none";
  if (authMethod !== "none") {
    invalidMetadata("token_endpoint_auth_method must be none");
  }

  for (const credentialProperty of [
    "client_id",
    "client_secret",
    "client_secret_expires_at",
    "registration_access_token",
    "registration_client_uri",
  ]) {
    if (metadata[credentialProperty] !== undefined) {
      invalidMetadata(`${credentialProperty} must not be provided`);
    }
  }
}

function registrationBody(
  request: NodeJS.ReadableStream,
): Record<string, unknown> | undefined {
  const body = (request as NodeJS.ReadableStream & { body?: unknown }).body;
  return isPlainObject(body) ? body : undefined;
}

function cookieKeys(encryptionKey: Uint8Array): Buffer[] {
  return [
    createHmac("sha256", encryptionKey)
      .update("mailcow-mcp:oidc-cookie-signing:v1", "utf8")
      .digest(),
  ];
}

function revokingTokenResource(token: {
  kind: string;
  aud?: unknown;
  resource?: unknown;
}): string | null {
  const value = token.kind === "AccessToken" ? token.aud : token.resource;
  if (typeof value === "string" && value !== "") {
    return value;
  }
  return Array.isArray(value) &&
    value.length === 1 &&
    typeof value[0] === "string" &&
    value[0] !== ""
    ? value[0]
    : null;
}

export async function createOidcProvider(
  dependencies: CreateOidcProviderDependencies,
): Promise<Provider> {
  const {
    pool,
    issuer,
    resource,
    encryptionKey,
    env = process.env,
  } = dependencies;
  const envPolicy = loadProviderPolicy(env);
  const allowedRedirectUris =
    dependencies.allowedRedirectUris ?? envPolicy.allowedRedirectUris;
  const allowLoopbackRedirects =
    dependencies.allowLoopbackRedirects ??
    envPolicy.allowLoopbackRedirects;
  const allowedRedirectSet = new Set(allowedRedirectUris);
  for (const allowedRedirectUri of allowedRedirectSet) {
    validateRedirectUri(allowedRedirectUri, allowedRedirectSet, false);
  }
  const signingJwk: JWK = await loadOrCreateSigningJwk(pool, encryptionKey);
  const configuration: Configuration = {
    adapter: MariaDbOidcAdapter.factory(pool, encryptionKey),
    clientAuthMethods: ["none"],
    clientDefaults: {
      grant_types: [...allowedGrantTypes],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
    cookies: { keys: cookieKeys(encryptionKey) },
    features: {
      devInteractions: { enabled: false },
      dPoP: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      registration: {
        enabled: true,
        issueRegistrationAccessToken: false,
      },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => resource.href,
        useGrantedResource: () => true,
        getResourceServerInfo: (_context, requestedResource) => {
          if (requestedResource !== resource.href) {
            throw new errors.InvalidTarget(
              "only the configured MCP resource is allowed",
            );
          }
          return {
            accessTokenFormat: "opaque",
            accessTokenTTL: 900,
            audience: resource.href,
            scope: scopeString,
          };
        },
      },
      revocation: {
        enabled: true,
        allowedPolicy: async (context, client, token) => {
          if (token.clientId !== client.clientId) {
            return false;
          }
          if (
            token.kind !== "AccessToken" &&
            token.kind !== "RefreshToken"
          ) {
            return true;
          }
          const accountId = token.accountId;
          const grantId = token.grantId;
          const tokenResource = revokingTokenResource(token);
          if (
            dependencies.protocolGrantRevoker === undefined ||
            typeof accountId !== "string" ||
            accountId === "" ||
            typeof token.clientId !== "string" ||
            token.clientId === "" ||
            typeof grantId !== "string" ||
            grantId === "" ||
            tokenResource === null ||
            tokenResource !== dependencies.resource.href
          ) {
            throw new Error("durable grant revocation is unavailable");
          }
          const lease =
            await dependencies.protocolGrantRevoker.prepare(
              accountId,
              token.clientId,
              tokenResource,
              grantId,
            );
          try {
            for (const sessionId of lease.sessionIds) {
              const session =
                await context.oidc.provider.Session.findByUid(sessionId);
              await session?.destroy();
            }
            revocationLeases.set(context, lease);
            return true;
          } catch (error) {
            lease.release();
            throw error;
          }
        },
      },
      rpInitiatedLogout: { enabled: false },
      userinfo: { enabled: false },
    },
    findAccount: (_context, accountId) => ({
      accountId,
      claims: () => ({ sub: accountId }),
    }),
    interactions: {
      url: (_context, interaction) =>
        `/mcp-login/${encodeURIComponent(interaction.uid)}`,
    },
    issueRefreshToken: () => true,
    jwks: { keys: [signingJwk] },
    pkce: { required: () => true },
    responseTypes: ["code"],
    rotateRefreshToken: true,
    routes: {
      authorization: "/oauth/auth",
      jwks: "/oauth/jwks",
      registration: registrationPath,
      revocation: "/oauth/revocation",
      token: "/oauth/token",
    },
    scopes: [],
    ttl: {
      AccessToken: 900,
      AuthorizationCode: 120,
      Grant: 2_592_000,
      Interaction: 600,
      RefreshToken: 2_592_000,
      Session: 2_592_000,
    },
  };
  const provider = new Provider(
    issuer.href.replace(/\/$/u, ""),
    configuration,
  );
  const revocationLeases =
    new WeakMap<object, ProtocolGrantRevocationLease>();
  provider.use(async (context, next) => {
    try {
      await next();
    } finally {
      const lease = revocationLeases.get(context);
      if (lease !== undefined) {
        revocationLeases.delete(context);
        lease.release();
      }
    }
  });
  provider.use(async (context, next) => {
    if (context.method === "GET" && context.path === "/oauth/auth") {
      if (!Object.hasOwn(context.query, "scope")) {
        context.query = { ...context.query, scope: scopeString };
      } else {
        const requestedScope = context.query.scope;
        const requestedScopes =
          typeof requestedScope === "string"
            ? requestedScope.split(" ").filter((scope) => scope !== "")
            : [];
        if (
          requestedScopes.length === 0 ||
          requestedScopes.some(
            (scope) =>
              !(MCP_OAUTH_SCOPES as readonly string[]).includes(scope),
          )
        ) {
          context.status = 400;
          context.body = {
            error: "invalid_scope",
            error_description: "only MCP resource scopes are allowed",
          };
          return;
        }
      }
    }

    await next();

    if (
      context.method === "GET" &&
      (
        context.path === "/.well-known/oauth-authorization-server" ||
        context.path === "/.well-known/openid-configuration"
      ) &&
      isPlainObject(context.body)
    ) {
      context.body.scopes_supported = [...MCP_OAUTH_SCOPES];
    }
  });

  provider.use(async (context, next) => {
    if (
      context.method !== "POST" ||
      context.path !== registrationPath
    ) {
      await next();
      return;
    }

    const metadata = registrationBody(context.req);
    try {
      validateDynamicClient(
        metadata,
        allowedRedirectSet,
        allowLoopbackRedirects,
      );
    } catch (error) {
      context.status = 400;
      context.body = {
        error: "invalid_client_metadata",
        error_description:
          error instanceof Error ? error.message : "invalid client metadata",
      };
      return;
    }

    Object.assign(metadata as DynamicClientMetadata, {
      grant_types: [...allowedGrantTypes],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    await next();
  });

  return provider;
}
