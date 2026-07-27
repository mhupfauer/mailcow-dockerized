import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import express from "express";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { promisify } from "node:util";

import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Provider } from "oidc-provider";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi,
} from "vitest";

import { createApp } from "../../src/app.js";
import {
  DEFAULT_OAUTH_REDIRECT_URIS,
  MCP_OAUTH_SCOPES,
  createOidcProvider,
} from "../../src/auth/oidc-provider.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";
import { initializeDatabase } from "../../src/db/init.js";
import { runMigrations } from "../../src/db/migrations.js";
import { createPool } from "../../src/db/pool.js";
import { startProductionServer } from "../../src/server.js";

const rootPassword = "root-password-for-oauth-policy-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const databasePassword = "b".repeat(64);
const encryptionKeyHex =
  "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
const issuer = new URL("https://mail.example.test");
const resource = new URL("https://mail.example.test/mcp");
const redirectUri = "https://claude.ai/api/mcp/auth_callback";
const execFileAsync = promisify(execFile);

interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  json(): unknown;
}

interface ExpiryRow extends RowDataPacket {
  model: string;
  remaining: number;
}

interface CountRow extends RowDataPacket {
  count: number;
}

interface StateRow extends RowDataPacket {
  stateValue: string;
}

function record(value: unknown): Record<string, unknown> {
  expect(value).toBeTypeOf("object");
  expect(value).not.toBeNull();
  expect(Array.isArray(value)).toBe(false);
  return value as Record<string, unknown>;
}

class HttpClient {
  private readonly cookies = new Map<string, string>();

  constructor(private readonly port: number) {}

  async request(
    path: string,
    {
      method = "GET",
      headers = {},
      body,
    }: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
    } = {},
  ): Promise<HttpResponse> {
    const cookie = [...this.cookies.entries()]
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
    const requestHeaders: Record<string, string> = {
      host: issuer.host,
      "x-forwarded-proto": "https",
      ...headers,
    };
    if (cookie !== "") {
      requestHeaders.cookie = cookie;
    }
    if (body !== undefined) {
      requestHeaders["content-length"] = Buffer.byteLength(body).toString();
    }

    return new Promise<HttpResponse>((resolve, reject) => {
      const request = httpRequest(
        {
          host: "127.0.0.1",
          port: this.port,
          path,
          method,
          headers: requestHeaders,
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () => {
            for (const setCookie of response.headers["set-cookie"] ?? []) {
              const pair = setCookie.split(";", 1)[0];
              const separator = pair.indexOf("=");
              if (separator > 0) {
                const name = pair.slice(0, separator);
                const value = pair.slice(separator + 1);
                if (value === "") {
                  this.cookies.delete(name);
                } else {
                  this.cookies.set(name, value);
                }
              }
            }

            const responseBody = Buffer.concat(chunks).toString("utf8");
            resolve({
              status: response.statusCode ?? 0,
              headers: response.headers,
              body: responseBody,
              json: () => JSON.parse(responseBody),
            });
          });
        },
      );
      request.on("error", reject);
      if (body !== undefined) {
        request.write(body);
      }
      request.end();
    });
  }

  get(path: string): Promise<HttpResponse> {
    return this.request(path);
  }

  postJson(
    path: string,
    body: unknown,
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    return this.request(path, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
  }

  postForm(path: string, body: URLSearchParams): Promise<HttpResponse> {
    return this.request(path, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  }
}

async function startServer(
  provider: Provider,
  { approveInteractions = false }: { approveInteractions?: boolean } = {},
): Promise<{ client: HttpClient; close(): Promise<void> }> {
  const harness = express();

  if (approveInteractions) {
    harness.get("/mcp-login/:interaction", async (request, response, next) => {
      try {
        const interaction = await provider.interactionDetails(request, response);

        if (interaction.prompt.name === "login") {
          await provider.interactionFinished(
            request,
            response,
            { login: { accountId: "test-account-id" } },
            { mergeWithLastSubmission: false },
          );
          return;
        }

        if (interaction.prompt.name !== "consent") {
          throw new Error(`unexpected interaction ${interaction.prompt.name}`);
        }

        const params = interaction.params as Record<string, unknown>;
        const clientId = params.client_id;
        const requestedScopes = params.scope;
        if (
          typeof clientId !== "string" ||
          typeof requestedScopes !== "string"
        ) {
          throw new Error("authorization interaction lacks client or scope");
        }

        let grant =
          interaction.grantId === undefined
            ? undefined
            : await provider.Grant.find(interaction.grantId);
        grant ??= new provider.Grant({
          accountId: "test-account-id",
          clientId,
        });
        grant.addResourceScope(resource.href, requestedScopes);
        const grantId = await grant.save();

        await provider.interactionFinished(
          request,
          response,
          { consent: { grantId } },
          { mergeWithLastSubmission: false },
        );
      } catch (error) {
        next(error);
      }
    });
  }

  harness.use(
    createApp({
      readiness: async () => true,
      resourceMetadataUrl: new URL(
        "/.well-known/oauth-protected-resource/mcp",
        issuer,
      ),
      oidcProvider: provider,
    }),
  );

  const server = harness.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address() as AddressInfo;

  return {
    client: new HttpClient(address.port),
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

function validRegistration(
  callback = redirectUri,
  metadata: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    redirect_uris: [callback],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...metadata,
  };
}

async function register(
  client: HttpClient,
  callback = redirectUri,
  metadata: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const response = await client.postJson(
    "/oauth/reg",
    validRegistration(callback, metadata),
  );
  expect(response.status).toBe(201);
  return record(response.json());
}

function authorizationPath(
  clientId: string,
  {
    callback = redirectUri,
    codeChallenge,
    codeChallengeMethod,
    requestedResource = resource.href,
    scope,
  }: {
    callback?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    requestedResource?: string;
    scope?: string | null;
  },
): string {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callback,
    response_type: "code",
    resource: requestedResource,
  });
  if (codeChallenge !== undefined) {
    query.set("code_challenge", codeChallenge);
  }
  if (codeChallengeMethod !== undefined) {
    query.set("code_challenge_method", codeChallengeMethod);
  }
  if (scope !== undefined && scope !== null) {
    query.set("scope", scope);
  }
  return `/oauth/auth?${query.toString()}`;
}

async function followAuthorization(
  client: HttpClient,
  initialPath: string,
  callback = redirectUri,
): Promise<URL> {
  let path = initialPath;
  const visited: string[] = [];

  for (let redirects = 0; redirects < 10; redirects += 1) {
    const response = await client.get(path);
    expect(response.status).toBe(303);
    const location = response.headers.location;
    expect(location).toBeTypeOf("string");
    const target = new URL(location as string, issuer);
    visited.push(`${target.pathname}${target.search}`);

    if (target.origin + target.pathname === callback) {
      return target;
    }
    path = `${target.pathname}${target.search}`;
  }

  throw new Error(
    `authorization flow exceeded redirect limit: ${visited.join(" -> ")}`,
  );
}

async function issueTokens(
  provider: Provider,
  client: HttpClient,
  { scope }: { scope?: string | null } = {},
): Promise<{
  clientId: string;
  accessToken: string;
  refreshToken: string;
  tokenResponse: Record<string, unknown>;
}> {
  const registration = await register(client);
  const clientId = registration.client_id;
  expect(clientId).toBeTypeOf("string");
  const verifier = "v".repeat(64);
  const challenge = createHash("sha256")
    .update(verifier, "ascii")
    .digest("base64url");
  const callback = await followAuthorization(
    client,
    authorizationPath(clientId as string, {
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      scope,
    }),
  );
  const code = callback.searchParams.get("code");
  expect(code).not.toBeNull();

  const codeModel = await provider.AuthorizationCode.find(code as string);
  expect(codeModel?.codeChallenge).toBe(challenge);
  expect(codeModel?.codeChallengeMethod).toBe("S256");

  const tokenResponse = await client.postForm(
    "/oauth/token",
    new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId as string,
      redirect_uri: redirectUri,
      code: code as string,
      code_verifier: verifier,
      resource: resource.href,
    }),
  );
  expect(tokenResponse.status).toBe(200);
  const tokenBody = record(tokenResponse.json());
  expect(tokenBody.access_token).toBeTypeOf("string");
  expect(tokenBody.refresh_token).toBeTypeOf("string");

  return {
    clientId: clientId as string,
    accessToken: tokenBody.access_token as string,
    refreshToken: tokenBody.refresh_token as string,
    tokenResponse: tokenBody,
  };
}

describe("OAuth provider policy", () => {
  let container: StartedTestContainer;
  let pool: Pool;
  let provider: Provider;
  let host: string;
  let port: number;

  beforeAll(async () => {
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();

    host = container.getHost();
    port = container.getMappedPort(3306);
    await initializeDatabase({
      host,
      port,
      rootPassword,
      databaseName,
      databaseUser,
      databasePassword,
    });
    pool = createPool({
      host,
      port,
      database: databaseName,
      user: databaseUser,
      password: databasePassword,
    });
    await runMigrations(pool);
  }, 60_000);

  beforeEach(async () => {
    await pool.query("DELETE FROM oidc_objects");
    await pool.query("DELETE FROM service_state");
    provider = await createOidcProvider({
      pool,
      issuer,
      resource,
      encryptionKey: Buffer.from(encryptionKeyHex, "hex"),
    });
  });

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  test("advertises only the reviewed code, refresh, public-client, S256, and endpoint policy", async () => {
    const running = await startServer(provider);
    try {
      const response = await running.client.get(
        "/.well-known/oauth-authorization-server",
      );

      expect(response.status).toBe(200);
      expect(response.json()).toMatchObject({
        issuer: issuer.href.replace(/\/$/, ""),
        authorization_endpoint: `${issuer.href}oauth/auth`,
        token_endpoint: `${issuer.href}oauth/token`,
        registration_endpoint: `${issuer.href}oauth/reg`,
        revocation_endpoint: `${issuer.href}oauth/revocation`,
        jwks_uri: `${issuer.href}oauth/jwks`,
        grant_types_supported: ["authorization_code", "refresh_token"],
        response_types_supported: ["code"],
        token_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: MCP_OAUTH_SCOPES,
      });
      const metadata = record(response.json());
      expect(metadata).not.toHaveProperty("userinfo_endpoint");
      expect(metadata).not.toHaveProperty("introspection_endpoint");
      expect(metadata).not.toHaveProperty(
        "pushed_authorization_request_endpoint",
      );
      expect(metadata).not.toHaveProperty("end_session_endpoint");
      const oidcDiscovery = await running.client.get(
        "/.well-known/openid-configuration",
      );
      expect(oidcDiscovery.status).toBe(200);
      expect(oidcDiscovery.json()).toMatchObject({
        issuer: issuer.href.replace(/\/$/, ""),
        scopes_supported: MCP_OAUTH_SCOPES,
      });
      expect(record(oidcDiscovery.json())).not.toHaveProperty(
        "userinfo_endpoint",
      );

      const live = await running.client.get("/health/live");
      expect(live.status).toBe(200);
      expect(live.json()).toEqual({ status: "live" });
      const mcp = await running.client.request("/mcp", { method: "POST" });
      expect(mcp.status).toBe(401);
      expect(mcp.headers["www-authenticate"]).toBe(
        'Bearer resource_metadata="https://mail.example.test/.well-known/oauth-protected-resource/mcp"',
      );
    } finally {
      await running.close();
    }
  });

  test("production entrypoint composes database-backed OAuth routes", async () => {
    const production = await startProductionServer(
      {
        MAILCOW_HOSTNAME: issuer.hostname,
        MCP_PORT: "3000",
        MCP_DBHOST: host,
        MCP_DBPORT: port.toString(),
        MCP_DBNAME: databaseName,
        MCP_DBUSER: databaseUser,
        MCP_DBPASS: databasePassword,
        MCP_ENCRYPTION_KEY: encryptionKeyHex,
      },
      { port: 0 },
    );
    const address = production.server.address() as AddressInfo;
    const client = new HttpClient(address.port);
    try {
      const readiness = await client.get("/health/ready");
      expect(readiness.status).toBe(200);

      const discovery = await client.get(
        "/.well-known/oauth-authorization-server",
      );
      expect(discovery.status).toBe(200);
      expect(discovery.json()).toMatchObject({
        authorization_endpoint: `${issuer.href}oauth/auth`,
        token_endpoint: `${issuer.href}oauth/token`,
        registration_endpoint: `${issuer.href}oauth/reg`,
      });

      const registration = await register(client);
      expect(registration.client_id).toBeTypeOf("string");

      const jwks = await client.get("/oauth/jwks");
      expect(jwks.status).toBe(200);
      expect(record(jwks.json()).keys).toBeInstanceOf(Array);

      const token = await client.postForm(
        "/oauth/token",
        new URLSearchParams({
          grant_type: "authorization_code",
          client_id: registration.client_id as string,
          code: "not-a-real-code",
          redirect_uri: redirectUri,
          code_verifier: "v".repeat(64),
        }),
      );
      expect(token.status).toBe(400);
      expect(token.json()).toMatchObject({ error: "invalid_grant" });
    } finally {
      await production.close();
    }
  });

  test.each([
    ["unapproved host", { redirect_uris: ["https://evil.example/cb"] }],
    [
      "allowlisted path suffix",
      {
        redirect_uris: [
          "https://claude.ai/api/mcp/auth_callback/extra",
        ],
      },
    ],
    [
      "redirect URI userinfo",
      {
        redirect_uris: [
          "https://user:password@claude.ai/api/mcp/auth_callback",
        ],
      },
    ],
    [
      "redirect URI fragment",
      {
        redirect_uris: [
          "https://claude.ai/api/mcp/auth_callback#fragment",
        ],
      },
    ],
    [
      "empty loopback redirect fragment",
      {
        redirect_uris: ["http://localhost:33418/callback#"],
      },
    ],
    [
      "non-loopback private HTTP address",
      { redirect_uris: ["http://192.168.1.10/cb"] },
    ],
    ["extra grant", { grant_types: ["authorization_code", "client_credentials"] }],
    ["missing authorization code grant", { grant_types: ["refresh_token"] }],
    ["extra response type", { response_types: ["code", "token"] }],
    ["implicit response type", { response_types: ["token"] }],
    ["secret auth method", { token_endpoint_auth_method: "client_secret_basic" }],
    ["client credentials", { client_secret: "must-not-be-accepted" }],
  ])("rejects DCR metadata containing %s", async (_caseName, override) => {
    const running = await startServer(provider);
    try {
      const response = await running.client.postJson(
        "/oauth/reg",
        validRegistration(redirectUri, override),
      );

      expect(response.status).toBe(400);
      expect(response.json()).toMatchObject({
        error: "invalid_client_metadata",
      });
    } finally {
      await running.close();
    }
  });

  test("rejects network-active DCR metadata without an outbound request", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("outbound request attempted"));
    const running = await startServer(provider);
    try {
      const response = await running.client.postJson(
        "/oauth/reg",
        validRegistration(redirectUri, {
          sector_identifier_uri:
            "https://169.254.169.254/latest/meta-data/",
        }),
      );

      expect(response.status).toBe(400);
      expect(response.json()).toMatchObject({
        error: "invalid_client_metadata",
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
      await running.close();
    }
  });

  test.each([
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://127.0.0.1:33418/callback",
    "http://[::1]:33418/callback",
    "http://localhost:33418/callback",
  ])("accepts the exact reviewed redirect %s", async (callback) => {
    const running = await startServer(provider);
    try {
      const registration = await register(running.client, callback);

      expect(registration.redirect_uris).toEqual([callback]);
      expect(registration.grant_types).toEqual([
        "authorization_code",
        "refresh_token",
      ]);
      expect(registration.response_types).toEqual(["code"]);
      expect(registration.token_endpoint_auth_method).toBe("none");
      expect(registration).not.toHaveProperty("client_secret");
    } finally {
      await running.close();
    }
  });

  test.each([
    "http://127.0.0.1:33418/callback",
    "http://[::1]:33418/callback",
    "http://localhost:33418/callback",
  ])("rejects loopback redirect %s when loopback support is off", async (callback) => {
    const noLoopbackProvider = await createOidcProvider({
      pool,
      issuer,
      resource,
      encryptionKey: Buffer.from(encryptionKeyHex, "hex"),
      env: { MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS: "0" },
    });
    const running = await startServer(noLoopbackProvider);
    try {
      const response = await running.client.postJson(
        "/oauth/reg",
        validRegistration(callback),
      );

      expect(response.status).toBe(400);
      expect(response.json()).toMatchObject({
        error: "invalid_client_metadata",
      });
    } finally {
      await running.close();
    }
  });

  test("uses the pinned upstream parsed-body fallback and stores normalized registration in the real adapter", async () => {
    const running = await startServer(provider);
    try {
      const registration = await register(running.client);
      const clientId = registration.client_id;
      expect(clientId).toBeTypeOf("string");

      const storedClient = await provider.Client.find(clientId as string);
      expect(storedClient?.metadata()).toMatchObject({
        client_id: clientId,
        redirect_uris: [redirectUri],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      });
      const [rows] = await pool.query<CountRow[]>(
        "SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Client'",
      );
      expect(rows[0]?.count).toBe(1);
    } finally {
      await running.close();
    }
  });

  test("rate limits registration by the nearest forwarded client IP", async () => {
    const running = await startServer(provider);
    try {
      const firstClient = {
        "x-forwarded-for": "198.51.100.250, 203.0.113.10",
      };
      for (let attempt = 1; attempt <= 10; attempt += 1) {
        const response = await running.client.postJson(
          "/oauth/reg",
          validRegistration(),
          firstClient,
        );
        expect(response.status).toBe(201);
      }

      const rejected = await running.client.postJson(
        "/oauth/reg",
        validRegistration(),
        firstClient,
      );
      expect(rejected.status).toBe(429);
      const independentClient = await running.client.postJson(
        "/oauth/reg",
        validRegistration(),
        {
          "x-forwarded-for": "198.51.100.250, 203.0.113.11",
        },
      );
      expect(independentClient.status).toBe(201);
      const [rows] = await pool.query<CountRow[]>(
        "SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Client'",
      );
      expect(rows[0]?.count).toBe(11);
    } finally {
      await running.close();
    }
  });

  test("counts malformed, non-object, and oversized registration bodies before parsing", async () => {
    const running = await startServer(provider);
    const forwardedClient = {
      "content-type": "application/json",
      "x-forwarded-for": "198.51.100.250, 203.0.113.20",
    };
    const invalidBodies = [
      { body: "{", status: 400 },
      { body: "[]", status: 400 },
      { body: JSON.stringify("not-an-object"), status: 400 },
      {
        body: JSON.stringify({ padding: "x".repeat(60 * 1_024) }),
        status: 413,
      },
    ];
    try {
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const invalid = invalidBodies[attempt % invalidBodies.length]!;
        const response = await running.client.request("/oauth/reg", {
          method: "POST",
          headers: forwardedClient,
          body: invalid.body,
        });

        expect(response.status).toBe(invalid.status);
        expect(response.body.length).toBeLessThan(512);
        expect(response.json()).toMatchObject({
          error: "invalid_client_metadata",
        });
      }

      const rejected = await running.client.postJson(
        "/oauth/reg",
        validRegistration(),
        { "x-forwarded-for": forwardedClient["x-forwarded-for"] },
      );
      expect(rejected.status).toBe(429);
      expect(rejected.body.length).toBeLessThan(512);
      expect(rejected.json()).toMatchObject({
        error: "too_many_requests",
      });
      const [rows] = await pool.query<CountRow[]>(
        "SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Client'",
      );
      expect(rows[0]?.count).toBe(0);
    } finally {
      await running.close();
    }
  });

  test("rejects omitted and non-S256 PKCE before starting an interaction", async () => {
    const running = await startServer(provider);
    try {
      const registration = await register(running.client);
      const clientId = registration.client_id as string;

      const omitted = await running.client.get(
        authorizationPath(clientId, {}),
      );
      expect(omitted.status).toBe(303);
      expect(
        new URL(omitted.headers.location as string).searchParams.get("error"),
      ).toBe("invalid_request");

      const plain = await running.client.get(
        authorizationPath(clientId, {
          codeChallenge: "c".repeat(64),
          codeChallengeMethod: "plain",
        }),
      );
      expect(plain.status).toBe(303);
      expect(
        new URL(plain.headers.location as string).searchParams.get("error"),
      ).toBe("invalid_request");
    } finally {
      await running.close();
    }
  });

  test("rejects any resource other than the exact MCP URL", async () => {
    const running = await startServer(provider);
    try {
      const registration = await register(running.client);
      const verifier = "w".repeat(64);
      const challenge = createHash("sha256")
        .update(verifier, "ascii")
        .digest("base64url");
      const response = await running.client.get(
        authorizationPath(registration.client_id as string, {
          codeChallenge: challenge,
          codeChallengeMethod: "S256",
          requestedResource: `${resource.href}/extra`,
        }),
      );

      expect(response.status).toBe(303);
      const callback = new URL(response.headers.location as string);
      expect(callback.searchParams.get("error")).toBe("invalid_target");
    } finally {
      await running.close();
    }
  });

  test("rejects scopes outside the three MCP resource scopes", async () => {
    const running = await startServer(provider);
    try {
      const registration = await register(running.client);
      const verifier = "s".repeat(64);
      const challenge = createHash("sha256")
        .update(verifier, "ascii")
        .digest("base64url");
      const response = await running.client.get(
        authorizationPath(registration.client_id as string, {
          codeChallenge: challenge,
          codeChallengeMethod: "S256",
          scope: "mail.read openid",
        }),
      );

      expect(response.status).toBe(400);
      expect(response.json()).toMatchObject({ error: "invalid_scope" });
    } finally {
      await running.close();
    }
  });

  test("issues only exact-audience opaque 15-minute tokens, two-minute codes, and 30-day refresh tokens", async () => {
    const running = await startServer(provider, { approveInteractions: true });
    try {
      const issued = await issueTokens(provider, running.client);

      expect(issued.accessToken).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(issued.accessToken).not.toContain(".");
      expect(issued.tokenResponse.expires_in).toBe(900);
      expect(
        new Set((issued.tokenResponse.scope as string).split(" ")),
      ).toEqual(new Set(MCP_OAUTH_SCOPES));

      const storedAccessToken = await provider.AccessToken.find(
        issued.accessToken,
      );
      expect(storedAccessToken).toMatchObject({
        accountId: "test-account-id",
        aud: resource.href,
        scope: MCP_OAUTH_SCOPES.join(" "),
      });

      const [rows] = await pool.query<ExpiryRow[]>(
        `SELECT
          model,
          TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), expires_at) AS remaining
        FROM oidc_objects
        WHERE model IN (
          'AuthorizationCode', 'AccessToken', 'RefreshToken', 'Grant'
        )`,
      );
      const remaining = new Map(
        rows.map((row) => [row.model, Number(row.remaining)]),
      );
      expect(remaining.get("AuthorizationCode")).toBeGreaterThanOrEqual(110);
      expect(remaining.get("AuthorizationCode")).toBeLessThanOrEqual(120);
      expect(remaining.get("AccessToken")).toBeGreaterThanOrEqual(890);
      expect(remaining.get("AccessToken")).toBeLessThanOrEqual(900);
      expect(remaining.get("RefreshToken")).toBeGreaterThanOrEqual(
        2_592_000 - 10,
      );
      expect(remaining.get("RefreshToken")).toBeLessThanOrEqual(2_592_000);
      expect(remaining.get("Grant")).toBeGreaterThanOrEqual(
        2_592_000 - 10,
      );
      expect(remaining.get("Grant")).toBeLessThanOrEqual(2_592_000);
    } finally {
      await running.close();
    }
  });

  test("persists clients, opaque tokens, and one encrypted signing key across fresh provider and process restarts", async () => {
    const running = await startServer(provider, { approveInteractions: true });
    try {
      const firstJwksResponse = await running.client.get("/oauth/jwks");
      expect(firstJwksResponse.status).toBe(200);
      const firstJwks = record(firstJwksResponse.json());
      const firstKey = record((firstJwks.keys as unknown[])[0]);
      expect(firstKey.kty).toBe("RSA");
      expect(firstKey).not.toHaveProperty("d");
      expect(firstKey).not.toHaveProperty("p");
      expect(firstKey).not.toHaveProperty("q");

      const issued = await issueTokens(provider, running.client);
      const [stateRows] = await pool.query<StateRow[]>(
        `SELECT CAST(state_value AS CHAR) AS stateValue
        FROM service_state
        WHERE state_key = 'oidc-signing-key'`,
      );
      expect(stateRows).toHaveLength(1);
      expect(stateRows[0]?.stateValue).toMatch(
        /^\{"version":1,"envelope":"v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"\}$/,
      );
      expect(stateRows[0]?.stateValue).not.toContain('"d"');
      expect(stateRows[0]?.stateValue).not.toContain(
        firstKey.n as string,
      );
      const persistedState = JSON.parse(
        stateRows[0]?.stateValue ?? "",
      ) as { envelope?: unknown };
      expect(persistedState.envelope).toBeTypeOf("string");
      const privatePlaintext = await new AesGcmCredentialVault(
        Buffer.from(encryptionKeyHex, "hex"),
      ).open(
        "oidc-signing-key",
        "oidc-signing-key",
        persistedState.envelope as string,
      );
      let containsPrivateMaterial = false;
      try {
        const privateJwk: unknown = JSON.parse(
          Buffer.from(privatePlaintext).toString("utf8"),
        );
        containsPrivateMaterial =
          typeof privateJwk === "object" &&
          privateJwk !== null &&
          typeof (privateJwk as Record<string, unknown>).d === "string";
      } finally {
        Buffer.from(
          privatePlaintext.buffer,
          privatePlaintext.byteOffset,
          privatePlaintext.byteLength,
        ).fill(0);
      }
      expect(containsPrivateMaterial).toBe(true);

      const restarted = await createOidcProvider({
        pool,
        issuer,
        resource,
        encryptionKey: Buffer.from(encryptionKeyHex, "hex"),
      });
      await expect(
        restarted.Client.find(issued.clientId),
      ).resolves.toBeDefined();
      await expect(
        restarted.AccessToken.find(issued.accessToken),
      ).resolves.toMatchObject({
        aud: resource.href,
        accountId: "test-account-id",
      });

      const childCode = `
        import { createPool } from "./src/db/pool.ts";
        import { createOidcProvider } from "./src/auth/oidc-provider.ts";
        const pool = createPool({
          host: process.env.TEST_DB_HOST,
          port: Number(process.env.TEST_DB_PORT),
          database: process.env.TEST_DB_NAME,
          user: process.env.TEST_DB_USER,
          password: process.env.TEST_DB_PASSWORD,
        });
        const provider = await createOidcProvider({
          pool,
          issuer: new URL(process.env.TEST_ISSUER),
          resource: new URL(process.env.TEST_RESOURCE),
          encryptionKey: Buffer.from(process.env.TEST_ENCRYPTION_KEY, "hex"),
        });
        provider.proxy = true;
        const server = provider.listen(0);
        await new Promise((resolve) => server.once("listening", resolve));
        const address = server.address();
        const response = await fetch("http://127.0.0.1:" + address.port + "/oauth/jwks");
        const body = await response.text();
        process.stdout.write("PUBLIC_JWKS:" + body);
        await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
        await pool.end();
      `;
      const child = await execFileAsync(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "--eval", childCode],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            TEST_DB_HOST: host,
            TEST_DB_PORT: port.toString(),
            TEST_DB_NAME: databaseName,
            TEST_DB_USER: databaseUser,
            TEST_DB_PASSWORD: databasePassword,
            TEST_ISSUER: issuer.href,
            TEST_RESOURCE: resource.href,
            TEST_ENCRYPTION_KEY: encryptionKeyHex,
          },
        },
      );
      const childJwks = JSON.parse(
        child.stdout.slice(child.stdout.indexOf("PUBLIC_JWKS:") + 12),
      );
      expect(childJwks).toEqual(firstJwks);
    } finally {
      await running.close();
    }
  }, 30_000);

  test("allows exactly one simultaneous refresh rotation and no loser descendant", async () => {
    const running = await startServer(provider, { approveInteractions: true });
    try {
      const issued = await issueTokens(provider, running.client);
      await pool.query("DROP TRIGGER IF EXISTS delay_refresh_consume");
      await pool.query(
        `CREATE TRIGGER delay_refresh_consume
        BEFORE UPDATE ON oidc_objects
        FOR EACH ROW
        SET @consume_delay = IF(
          OLD.model = 'RefreshToken'
            AND OLD.consumed_at IS NULL
            AND NEW.consumed_at IS NOT NULL,
          SLEEP(0.2),
          0
        )`,
      );
      const refreshRequest = () =>
        running.client.postForm(
          "/oauth/token",
          new URLSearchParams({
            grant_type: "refresh_token",
            client_id: issued.clientId,
            refresh_token: issued.refreshToken,
            resource: resource.href,
          }),
        );
      const responses = await Promise.all([
        refreshRequest(),
        refreshRequest(),
      ]);
      expect(responses.map((response) => response.status).sort()).toEqual([
        200,
        400,
      ]);
      const rotated = record(
        responses.find((response) => response.status === 200)?.json(),
      );
      expect(rotated.refresh_token).toBeTypeOf("string");
      expect(rotated.refresh_token).not.toBe(issued.refreshToken);
      expect(
        responses.find((response) => response.status === 400)?.json(),
      ).toMatchObject({
        error: "invalid_grant",
      });
      const [refreshRows] = await pool.query<CountRow[]>(
        `SELECT COUNT(*) AS count
        FROM oidc_objects
        WHERE model = 'RefreshToken'`,
      );
      const [accessRows] = await pool.query<CountRow[]>(
        `SELECT COUNT(*) AS count
        FROM oidc_objects
        WHERE model = 'AccessToken'`,
      );
      expect(refreshRows[0]?.count).toBe(2);
      expect(accessRows[0]?.count).toBe(2);
    } finally {
      await pool.query("DROP TRIGGER IF EXISTS delay_refresh_consume");
      await running.close();
    }
  });

  test("revokes an issued opaque access token through the protocol endpoint", async () => {
    const running = await startServer(provider, { approveInteractions: true });
    try {
      const issued = await issueTokens(provider, running.client);
      await expect(
        provider.AccessToken.find(issued.accessToken),
      ).resolves.toBeDefined();

      const response = await running.client.postForm(
        "/oauth/revocation",
        new URLSearchParams({
          client_id: issued.clientId,
          token: issued.accessToken,
          token_type_hint: "access_token",
        }),
      );

      expect(response.status).toBe(200);
      await expect(
        provider.AccessToken.find(issued.accessToken),
      ).resolves.toBeUndefined();
    } finally {
      await running.close();
    }
  });

  test("uses exactly the two default HTTPS callbacks when none are configured", () => {
    expect(DEFAULT_OAUTH_REDIRECT_URIS).toEqual([
      "https://claude.ai/api/mcp/auth_callback",
      "https://claude.com/api/mcp/auth_callback",
    ]);
  });
});
