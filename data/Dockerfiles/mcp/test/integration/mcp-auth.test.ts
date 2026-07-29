import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { describe, expect, test, vi } from "vitest";

import { MariaDbConsentAuthorizationRepository } from "../../src/auth/authorization-state.js";
import { ConsentAuthorizationCodec } from "../../src/auth/consent-authorization-codec.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";
import {
  accountIdForMailbox,
  app,
  authPath,
  client,
  encryptionKey,
  hidden,
  HttpClient,
  installInteractionsFixture,
  issuer,
  locationPath,
  loginPageFor,
  provider,
  pool,
  reachConsentFor,
  redirectUri,
  resource,
  restartProviderAndApp,
  server,
  startApp,
} from "./support/interactions-fixture.js";

const protocolVersion = "2025-11-25";

function initializeRequest(): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: "mcp-auth-test", version: "1.0.0" },
    },
  };
}

function deferred(): {
  promise: Promise<void>;
  resolve(): void;
} {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function issueAccessToken(
  httpClient: HttpClient,
  scope: string,
  mailbox = "user@example.test",
): Promise<{ accessToken: string; refreshToken: string; clientId: string }> {
  const registration = await httpClient.postJson("/oauth/reg", {
    redirect_uris: [redirectUri],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  });
  expect(registration.status).toBe(201);
  const clientId = (registration.json() as Record<string, unknown>)
    .client_id as string;
  expect(clientId).toBeTypeOf("string");
  const login = await loginPageFor(httpClient, clientId, scope);
  const loggedIn = await httpClient.postForm(login.path, {
    csrf: hidden(login.response.body, "csrf"),
    mailbox,
    app_password: "app-password",
  });
  const consent = await reachConsentFor(httpClient, loggedIn);
  const approved = await httpClient.postForm(consent.path, {
    csrf: hidden(consent.response.body, "csrf"),
    decision: "approve",
  });
  expect(approved.status).toBe(303);
  const callback = await httpClient.get(locationPath(approved));
  const code = new URL(callback.headers.location as string).searchParams.get(
    "code",
  );
  expect(code).toBeTypeOf("string");

  const token = await httpClient.postForm("/oauth/token", {
    grant_type: "authorization_code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code: code as string,
    code_verifier: "v".repeat(64),
    resource: resource.href,
  });
  expect(token.status).toBe(200);
  const body = token.json() as Record<string, unknown>;
  expect(body.access_token).toBeTypeOf("string");
  expect(body.refresh_token).toBeTypeOf("string");
  return {
    accessToken: body.access_token as string,
    refreshToken: body.refresh_token as string,
    clientId,
  };
}

async function mcpRequest(
  method: "POST" | "GET" | "DELETE",
  bearer: string | undefined,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  return client.request("/mcp", {
    method,
    headers: {
      accept: "application/json, text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function mcpPost(
  bearer: string | undefined,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return mcpRequest("POST", bearer, body, headers);
}

async function openAuthenticatedMcpGet(
  bearer: string,
  sessionId: string,
): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
}> {
  const port = (server.address() as AddressInfo).port;
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "GET",
        headers: {
          accept: "text/event-stream",
          authorization: `Bearer ${bearer}`,
          host: issuer.host,
          "mcp-protocol-version": protocolVersion,
          "mcp-session-id": sessionId,
          "x-forwarded-proto": "https",
        },
      },
      (response) => {
        resolve({
          status: response.statusCode ?? 0,
          headers: response.headers,
        });
        response.destroy();
      },
    );
    request.on("error", reject);
    request.end();
  });
}

async function mintAccessToken(
  accessToken: string,
  clientId: string,
  expiresInSeconds: number,
): Promise<string> {
  const original = await provider.AccessToken.find(accessToken);
  const oidcClient = await provider.Client.find(clientId);
  expect(original).toBeDefined();
  expect(oidcClient).toBeDefined();
  const minted = new provider.AccessToken({
    client: oidcClient!,
    accountId: original!.accountId,
    aud: resource.href,
    scope: original!.scope ?? "mail.read",
    grantId: original!.grantId,
    gty: original!.gty,
  });
  minted.exp = Math.floor(Date.now() / 1_000) + expiresInSeconds;
  return minted.save(expiresInSeconds);
}

function authorizationRepository(): MariaDbConsentAuthorizationRepository {
  return new MariaDbConsentAuthorizationRepository(
    pool,
    new AesGcmCredentialVault(encryptionKey),
    resource.href,
  );
}

async function renewAuthorization(
  httpClient: HttpClient,
  clientId: string,
  scope: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  const login = await loginPageFor(httpClient, clientId, scope);
  expect(login.response.body).toContain('name="mailbox"');
  const loggedIn = await httpClient.postForm(login.path, {
    csrf: hidden(login.response.body, "csrf"),
    mailbox: "user@example.test",
    app_password: "app-password",
  });
  const consent = await reachConsentFor(httpClient, loggedIn);
  expect(consent.response.body).toContain(scope);
  const approved = await httpClient.postForm(consent.path, {
    csrf: hidden(consent.response.body, "csrf"),
    decision: "approve",
  });
  expect(approved.status).toBe(303);
  const callback = await httpClient.get(locationPath(approved));
  const code = new URL(callback.headers.location as string).searchParams.get(
    "code",
  );
  expect(code).toBeTypeOf("string");
  const token = await httpClient.postForm("/oauth/token", {
    grant_type: "authorization_code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code: code as string,
    code_verifier: "v".repeat(64),
    resource: resource.href,
  });
  expect(token.status).toBe(200);
  const body = token.json() as Record<string, unknown>;
  return {
    accessToken: body.access_token as string,
    refreshToken: body.refresh_token as string,
  };
}

describe("protected MCP Streamable HTTP", () => {
  installInteractionsFixture();

  test("publishes exact protected-resource metadata", async () => {
    const response = await client.get(
      "/.well-known/oauth-protected-resource/mcp",
    );

    expect(response.status).toBe(200);
    expect(response.json()).toEqual({
      resource: resource.href,
      authorization_servers: [issuer.href.replace(/\/$/u, "")],
      scopes_supported: ["mail.read", "mail.send", "mail.organize"],
    });
  });

  test("lets the provider publish canonical authorization-server metadata", async () => {
    const response = await client.get(
      "/.well-known/oauth-authorization-server",
    );

    expect(response.status).toBe(200);
    expect(response.json()).toMatchObject({
      issuer: issuer.href.replace(/\/$/u, ""),
      authorization_endpoint: `${issuer.href}oauth/auth`,
      token_endpoint: `${issuer.href}oauth/token`,
      registration_endpoint: `${issuer.href}oauth/reg`,
      revocation_endpoint: `${issuer.href}oauth/revocation`,
      jwks_uri: `${issuer.href}oauth/jwks`,
      scopes_supported: ["mail.read", "mail.send", "mail.organize"],
    });
  });

  test("requires a bearer token even when a fabricated session ID is supplied", async () => {
    const response = await mcpPost(undefined, initializeRequest(), {
      "mcp-session-id": "fabricated-session-id",
    });

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toContain(
      'resource_metadata="https://mail.example.test/.well-known/oauth-protected-resource/mcp"',
    );
  });

  test.each([
    ["malformed", "{"],
    ["oversized", JSON.stringify({ value: "x".repeat(110_000) })],
  ])(
    "authenticates before parsing an unauthenticated %s JSON body",
    async (_caseName, body) => {
      const response = await client.request("/mcp", {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body,
      });

      expect(response.status).toBe(401);
      expect(response.headers["www-authenticate"]).toContain(
        'resource_metadata="https://mail.example.test/.well-known/oauth-protected-resource/mcp"',
      );
      expect(response.json()).toMatchObject({ error: "invalid_token" });
    },
  );

  test.each(["GET", "DELETE"] as const)(
    "requires bearer authentication on %s",
    async (method) => {
      const response = await mcpRequest(method, undefined, undefined, {
        "mcp-session-id": "fabricated-session-id",
      });

      expect(response.status).toBe(401);
      expect(response.headers["www-authenticate"]).toContain(
        'resource_metadata="https://mail.example.test/.well-known/oauth-protected-resource/mcp"',
      );
    },
  );

  test("dispatches authenticated GET for a live session", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const initialized = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    const sessionId = initialized.headers["mcp-session-id"] as string;

    const response = await openAuthenticatedMcpGet(
      issued.accessToken,
      sessionId,
    );

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/event-stream");
    expect(response.headers["mcp-session-id"]).toBe(sessionId);
  });

  test("rejects an expired opaque bearer token", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    await pool.query(
      "UPDATE oidc_objects SET expires_at = UTC_TIMESTAMP(6) WHERE model = 'AccessToken'",
    );

    const response = await mcpPost(issued.accessToken, initializeRequest());

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test("rejects an opaque bearer token for a different resource audience", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(original).toBeDefined();
    expect(oidcClient).toBeDefined();
    const wrongAudience = new provider.AccessToken({
      client: oidcClient!,
      accountId: original!.accountId,
      aud: "https://wrong.example.test/mcp",
      scope: "mail.read",
      grantId: original!.grantId,
      gty: original!.gty,
    });
    const token = await wrongAudience.save(900);

    const response = await mcpPost(token, initializeRequest());

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test.each(["mail.send", "mail.organize"])(
    "initializes with the allowed %s-only scope",
    async (scope) => {
      const issued = await issueAccessToken(client, scope);

      const response = await mcpPost(issued.accessToken, initializeRequest());

      expect(response.status).toBe(200);
      expect(response.headers["mcp-session-id"]).toBeTypeOf("string");
      expect(response.body).toContain('"protocolVersion":"2025-11-25"');
    },
  );

  test("returns insufficient_scope for an authenticated token with no usable MCP scope", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(original).toBeDefined();
    expect(oidcClient).toBeDefined();
    const emptyScopeToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: original!.accountId,
      aud: resource.href,
      scope: "",
      grantId: original!.grantId,
      gty: original!.gty,
    }).save(900);

    const response = await mcpPost(emptyScopeToken, initializeRequest());

    expect(response.status).toBe(403);
    expect(response.headers["www-authenticate"]).toContain(
      'error="insufficient_scope"',
    );
  });

  test.each([
    [
      "revoked account",
      async (
        accountId: string,
        _clientId: string,
        _repository: MariaDbConsentAuthorizationRepository,
      ) => {
        await pool.query(
          `UPDATE accounts
           SET revoked_at = UTC_TIMESTAMP(6)
           WHERE id = UNHEX(REPLACE(?, '-', ''))`,
          [accountId],
        );
      },
    ],
    [
      "cleanup-pending consent",
      async (
        accountId: string,
        clientId: string,
        repository: MariaDbConsentAuthorizationRepository,
      ) => {
        await repository.beginClientCleanup(accountId, clientId);
      },
    ],
    [
      "quarantined consent",
      async (
        accountId: string,
        clientId: string,
        repository: MariaDbConsentAuthorizationRepository,
      ) => {
        await repository.quarantine(accountId, clientId);
      },
    ],
    [
      "revoked consent",
      async (
        accountId: string,
        clientId: string,
        repository: MariaDbConsentAuthorizationRepository,
      ) => {
        await repository.beginClientCleanup(accountId, clientId);
        await repository.completeClientCleanup(accountId, clientId);
      },
    ],
  ] as const)(
    "denies a provider token after durable authority becomes %s",
    async (_caseName, mutate) => {
      const issued = await issueAccessToken(client, "mail.read");
      const token = await provider.AccessToken.find(issued.accessToken);
      expect(token?.accountId).toBeTypeOf("string");
      const repository = new MariaDbConsentAuthorizationRepository(
        pool,
        new AesGcmCredentialVault(encryptionKey),
        resource.href,
      );

      await mutate(token!.accountId, issued.clientId, repository);
      const response = await mcpPost(
        issued.accessToken,
        initializeRequest(),
      );

      expect(response.status).toBe(401);
      expect(response.json()).toMatchObject({ error: "invalid_token" });
    },
  );

  test("denies a token whose grant does not match current durable consent", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(original).toBeDefined();
    expect(oidcClient).toBeDefined();
    const obsoleteGrant = new provider.Grant({
      accountId: original!.accountId,
      clientId: issued.clientId,
    });
    obsoleteGrant.addResourceScope(resource.href, "mail.read");
    const obsoleteGrantId = await obsoleteGrant.save();
    const obsoleteToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: original!.accountId,
      aud: resource.href,
      scope: "mail.read",
      grantId: obsoleteGrantId,
      gty: original!.gty,
    }).save(900);

    const response = await mcpPost(obsoleteToken, initializeRequest());

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test("denies a token whose scopes exceed current durable consent", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(original).toBeDefined();
    expect(oidcClient).toBeDefined();
    const broadToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: original!.accountId,
      aud: resource.href,
      scope: "mail.read mail.send",
      grantId: original!.grantId,
      gty: original!.gty,
    }).save(900);

    const response = await mcpPost(broadToken, initializeRequest());

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test("denies a token when encrypted durable consent names another resource", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    expect(original?.accountId).toBeTypeOf("string");
    const repository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
      resource.href,
    );
    const active = await repository.getActive(
      original!.accountId,
      issued.clientId,
    );
    expect(active).not.toBeNull();
    const wrongResource = "https://mail.example.test/another-resource";
    const codec = new ConsentAuthorizationCodec(
      new AesGcmCredentialVault(encryptionKey),
      wrongResource,
    );
    const mismatched = await codec.seal(original!.accountId, {
      ...active!,
      resource: wrongResource,
    });
    await pool.query(
      `UPDATE consents
       SET scopes = ?
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [mismatched, original!.accountId, issued.clientId],
    );

    const response = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test("denies a token when durable consent cannot be decoded", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const accountId = await accountIdForMailbox();
    await pool.query(
      `UPDATE consents
       SET scopes = '{"version":2}'
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, issued.clientId],
    );

    const response = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  test("denies a token when the durable authorization lookup fails", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const lookup = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "getActive",
      )
      .mockRejectedValueOnce(new Error("database unavailable"));

    const response = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    lookup.mockRestore();

    expect(response.status).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
    expect(response.body).not.toContain("database unavailable");
  });

  test("access-token revocation clears broad authority and narrow renewal cannot reuse old scope", async () => {
    const issued = await issueAccessToken(
      client,
      "mail.read mail.send",
    );
    const original = await provider.AccessToken.find(issued.accessToken);
    expect(original?.accountId).toBeTypeOf("string");
    expect(original?.grantId).toBeTypeOf("string");
    const repository = authorizationRepository();

    const revoked = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: issued.accessToken,
      token_type_hint: "access_token",
    });

    expect(revoked.status).toBe(200);
    expect(
      await repository.getStored(original!.accountId, issued.clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      scopes: [],
      sessionIds: [],
    });
    expect(
      (await repository.getStored(original!.accountId, issued.clientId))
        ?.grantId,
    ).toBeUndefined();
    const denied = await mcpPost(issued.accessToken, initializeRequest());
    expect(denied.status).toBe(401);

    const renewed = await renewAuthorization(
      client,
      issued.clientId,
      "mail.read",
    );
    const renewedModel = await provider.AccessToken.find(
      renewed.accessToken,
    );
    expect(renewedModel?.grantId).toBeTypeOf("string");
    expect(renewedModel?.grantId).not.toBe(original!.grantId);
    expect(
      await repository.getActive(original!.accountId, issued.clientId),
    ).toMatchObject({
      lifecycle: "active",
      grantId: renewedModel!.grantId,
      scopes: ["mail.read"],
    });

    const oldScopeStart = await client.get(
      authPath(issued.clientId, "mail.send"),
    );
    const oldScopePath = locationPath(oldScopeStart);
    expect(oldScopePath).toMatch(/^\/mcp-login\//u);
    const oldScopePrompt = await client.get(oldScopePath);
    expect(oldScopePrompt.status).toBe(200);
    expect(oldScopePrompt.body).toContain("mail.send");

    const oidcClient = await provider.Client.find(issued.clientId);
    expect(oidcClient).toBeDefined();
    const oldScopeToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: original!.accountId,
      aud: resource.href,
      scope: "mail.send",
      grantId: renewedModel!.grantId,
      gty: renewedModel!.gty,
    }).save(900);
    expect(
      (await mcpPost(oldScopeToken, initializeRequest())).status,
    ).toBe(401);

    const obsoleteRetry = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: issued.accessToken,
      token_type_hint: "access_token",
    });
    expect(obsoleteRetry.status).toBe(200);
    expect(
      await repository.getActive(original!.accountId, issued.clientId),
    ).toMatchObject({ grantId: renewedModel!.grantId });
    expect(
      (await mcpPost(renewed.accessToken, initializeRequest())).status,
    ).toBe(200);
  });

  test("refresh-token revocation clears matching durable consent before provider artifacts", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.RefreshToken.find(issued.refreshToken);
    expect(original?.accountId).toBeTypeOf("string");
    expect(original?.grantId).toBeTypeOf("string");
    const repository = authorizationRepository();

    const revoked = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: issued.refreshToken,
      token_type_hint: "refresh_token",
    });

    expect(revoked.status).toBe(200);
    expect(
      await repository.getStored(original!.accountId, issued.clientId),
    ).toMatchObject({
      lifecycle: "revoked",
      scopes: [],
      sessionIds: [],
    });
    expect(
      (await repository.getStored(original!.accountId, issued.clientId))
        ?.grantId,
    ).toBeUndefined();
    await expect(
      provider.AccessToken.find(issued.accessToken),
    ).resolves.toBeUndefined();
    await expect(
      provider.RefreshToken.find(issued.refreshToken),
    ).resolves.toBeUndefined();
  });

  test("fails protocol revocation closed before provider deletion when durable cleanup fails", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    expect(original?.accountId).toBeTypeOf("string");
    const cleanup = vi
      .spyOn(
        MariaDbConsentAuthorizationRepository.prototype,
        "revokeMatchingGrant",
      )
      .mockRejectedValueOnce(new Error("database unavailable"));

    const response = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: issued.accessToken,
      token_type_hint: "access_token",
    });
    cleanup.mockRestore();

    expect(response.status).toBeGreaterThanOrEqual(500);
    expect(response.body).not.toContain("database unavailable");
    await expect(
      provider.AccessToken.find(issued.accessToken),
    ).resolves.toBeDefined();
    expect(
      await authorizationRepository().getActive(
        original!.accountId,
        issued.clientId,
      ),
    ).not.toBeNull();
  });

  test("revoking an obsolete exact-client grant does not revoke newer durable consent", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const current = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(current?.accountId).toBeTypeOf("string");
    expect(current?.grantId).toBeTypeOf("string");
    expect(oidcClient).toBeDefined();
    const obsoleteGrant = new provider.Grant({
      accountId: current!.accountId,
      clientId: issued.clientId,
    });
    obsoleteGrant.addResourceScope(resource.href, "mail.read");
    const obsoleteGrantId = await obsoleteGrant.save();
    const obsoleteToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: current!.accountId,
      aud: resource.href,
      scope: "mail.read",
      grantId: obsoleteGrantId,
      gty: current!.gty,
    }).save(900);
    const repository = authorizationRepository();

    const response = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: obsoleteToken,
      token_type_hint: "access_token",
    });

    expect(response.status).toBe(200);
    expect(
      await repository.getActive(current!.accountId, issued.clientId),
    ).toMatchObject({ grantId: current!.grantId, scopes: ["mail.read"] });
    expect(
      (await mcpPost(issued.accessToken, initializeRequest())).status,
    ).toBe(200);
  });

  test("fails protocol revocation closed for a current grant token naming another resource", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const current = await provider.AccessToken.find(issued.accessToken);
    const oidcClient = await provider.Client.find(issued.clientId);
    expect(current?.accountId).toBeTypeOf("string");
    expect(current?.grantId).toBeTypeOf("string");
    expect(oidcClient).toBeDefined();
    const wrongResourceToken = await new provider.AccessToken({
      client: oidcClient!,
      accountId: current!.accountId,
      aud: "https://wrong.example.test/mcp",
      scope: "mail.read",
      grantId: current!.grantId,
      gty: current!.gty,
    }).save(900);

    const response = await client.postForm("/oauth/revocation", {
      client_id: issued.clientId,
      token: wrongResourceToken,
      token_type_hint: "access_token",
    });

    expect(response.status).toBeGreaterThanOrEqual(500);
    await expect(
      provider.AccessToken.find(wrongResourceToken),
    ).resolves.toBeDefined();
    await expect(
      provider.AccessToken.find(issued.accessToken),
    ).resolves.toBeDefined();
    expect(
      await authorizationRepository().getActive(
        current!.accountId,
        issued.clientId,
      ),
    ).toMatchObject({ grantId: current!.grantId });
    expect(
      (await mcpPost(issued.accessToken, initializeRequest())).status,
    ).toBe(200);
  });

  test("accepts authenticated MCP JSON bodies above the Express default limit", async () => {
    const issued = await issueAccessToken(client, "mail.read");

    const response = await mcpPost(issued.accessToken, {
      padding: "x".repeat(200_000),
    });

    expect(response.status).toBe(400);
    expect(response.json()).toMatchObject({ error: "invalid_request" });
  });

  test("caps total live sessions and recovers when a session closes", async () => {
    await startApp({ mcpMaximumTotalSessions: 1 });
    const issued = await issueAccessToken(client, "mail.read");
    const first = await mcpPost(issued.accessToken, initializeRequest());
    expect(first.status).toBe(200);

    const limited = await mcpPost(issued.accessToken, initializeRequest());
    expect(limited.status).toBe(503);
    expect(limited.headers["retry-after"]).toBeTypeOf("string");
    expect(limited.json()).toMatchObject({
      error: "session_capacity_exhausted",
    });

    const closed = await mcpRequest(
      "DELETE",
      issued.accessToken,
      undefined,
      {
        "mcp-session-id": first.headers["mcp-session-id"] as string,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(closed.status).toBe(200);
    const recovered = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    expect(recovered.status).toBe(200);
  });

  test("caps live sessions per account and client without blocking another authority", async () => {
    await startApp({ mcpMaximumSessionsPerAuthority: 1 });
    const firstAuthority = await issueAccessToken(client, "mail.read");
    const first = await mcpPost(
      firstAuthority.accessToken,
      initializeRequest(),
    );
    expect(first.status).toBe(200);

    const limited = await mcpPost(
      firstAuthority.accessToken,
      initializeRequest(),
    );
    expect(limited.status).toBe(429);
    expect(limited.headers["retry-after"]).toBeTypeOf("string");
    expect(limited.json()).toMatchObject({
      error: "authority_session_capacity_exhausted",
    });

    const otherHttpClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const otherAuthority = await issueAccessToken(
      otherHttpClient,
      "mail.read",
      "other@example.test",
    );
    const otherResponse = await mcpPost(
      otherAuthority.accessToken,
      initializeRequest(),
    );
    expect(otherResponse.status).toBe(200);

    const closed = await mcpRequest(
      "DELETE",
      firstAuthority.accessToken,
      undefined,
      {
        "mcp-session-id": first.headers["mcp-session-id"] as string,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(closed.status).toBe(200);
    const recovered = await mcpPost(
      firstAuthority.accessToken,
      initializeRequest(),
    );
    expect(recovered.status).toBe(200);
  });

  test("caps initializations in flight and recovers after completion", async () => {
    await startApp({ mcpMaximumInitializationsInFlight: 1 });
    const issued = await issueAccessToken(client, "mail.read");
    const entered = deferred();
    const release = deferred();
    const realHandle =
      StreamableHTTPServerTransport.prototype.handleRequest;
    let blockFirstInitialize = true;
    const gate = vi
      .spyOn(StreamableHTTPServerTransport.prototype, "handleRequest")
      .mockImplementation(async function (request, response, body) {
        if (
          blockFirstInitialize &&
          typeof body === "object" &&
          body !== null &&
          (body as { method?: unknown }).method === "initialize"
        ) {
          blockFirstInitialize = false;
          entered.resolve();
          await release.promise;
        }
        return realHandle.call(this, request, response, body);
      });

    try {
      const first = mcpPost(issued.accessToken, initializeRequest());
      await entered.promise;
      const limited = await mcpPost(
        issued.accessToken,
        initializeRequest(),
      );
      expect(limited.status).toBe(503);
      expect(limited.headers["retry-after"]).toBeTypeOf("string");
      expect(limited.json()).toMatchObject({
        error: "initialization_capacity_exhausted",
      });

      release.resolve();
      expect((await first).status).toBe(200);
      const recovered = await mcpPost(
        issued.accessToken,
        initializeRequest(),
      );
      expect(recovered.status).toBe(200);
    } finally {
      release.resolve();
      gate.mockRestore();
    }
  });

  test("rate-limits initialization per authority and recovers after the fixed window", async () => {
    let now = Date.now();
    await startApp({
      mcpNow: () => now,
      mcpInitializationsPerWindow: 1,
      mcpInitializationWindowMs: 1_000,
    });
    const issued = await issueAccessToken(client, "mail.read");
    const first = await mcpPost(issued.accessToken, initializeRequest());
    expect(first.status).toBe(200);
    const closed = await mcpRequest(
      "DELETE",
      issued.accessToken,
      undefined,
      {
        "mcp-session-id": first.headers["mcp-session-id"] as string,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(closed.status).toBe(200);

    const limited = await mcpPost(issued.accessToken, initializeRequest());
    expect(limited.status).toBe(429);
    expect(limited.headers["retry-after"]).toBe("1");
    expect(limited.json()).toMatchObject({
      error: "initialization_rate_limited",
    });

    now += 1_000;
    const recovered = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    expect(recovered.status).toBe(200);
  });

  test("initializes an account-bound session without exposing mailbox credentials", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const response = await mcpPost(issued.accessToken, initializeRequest());

    expect(response.status).toBe(200);
    expect(response.headers["mcp-session-id"]).toBeTypeOf("string");
    expect(response.body).toContain('"protocolVersion":"2025-11-25"');
    expect(response.body).not.toContain("user@example.test");
    expect(issued.accessToken).not.toContain("user@example.test");
    expect(issued.accessToken).not.toContain("app-password");
    expect(response.body).not.toContain("app-password");

    const tools = await mcpPost(issued.accessToken, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    }, {
      "mcp-session-id": response.headers["mcp-session-id"] as string,
      "mcp-protocol-version": protocolVersion,
    });
    expect(tools.status).toBe(200);
    expect(tools.body).toContain('"tools":[]');
  });

  test("terminates a session through authenticated DELETE", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const initialized = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    const sessionId = initialized.headers["mcp-session-id"] as string;
    const sessionHeaders = {
      "mcp-session-id": sessionId,
      "mcp-protocol-version": protocolVersion,
    };

    const deleted = await mcpRequest(
      "DELETE",
      issued.accessToken,
      undefined,
      sessionHeaders,
    );
    expect(deleted.status).toBe(200);

    const afterDelete = await mcpPost(
      issued.accessToken,
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
      sessionHeaders,
    );
    expect(afterDelete.status).toBe(404);
  });

  test("closes all sessions through the application lifecycle", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const initialized = await mcpPost(
      issued.accessToken,
      initializeRequest(),
    );
    const sessionId = initialized.headers["mcp-session-id"] as string;

    await (
      app as typeof app & { closeMcpSessions(): Promise<void> }
    ).closeMcpSessions();

    const response = await mcpPost(
      issued.accessToken,
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
      {
        "mcp-session-id": sessionId,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(response.status).toBe(404);
  });

  test("shutdown waits for an in-flight initialize and closes its session", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const entered = deferred();
    const release = deferred();
    const realHandle =
      StreamableHTTPServerTransport.prototype.handleRequest;
    let blockFirstInitialize = true;
    const gate = vi
      .spyOn(StreamableHTTPServerTransport.prototype, "handleRequest")
      .mockImplementation(async function (request, response, body) {
        if (
          blockFirstInitialize &&
          typeof body === "object" &&
          body !== null &&
          (body as { method?: unknown }).method === "initialize"
        ) {
          blockFirstInitialize = false;
          entered.resolve();
          await release.promise;
        }
        return realHandle.call(this, request, response, body);
      });

    let closeResult: number | undefined;
    let firstStatus = 0;
    let afterClosingStatus = 0;
    try {
      const firstInitialize = mcpPost(
        issued.accessToken,
        initializeRequest(),
      );
      await entered.promise;
      const closing = (
        app as typeof app & { closeMcpSessions(): Promise<number> }
      ).closeMcpSessions();
      const afterClosing = await mcpPost(
        issued.accessToken,
        initializeRequest(),
      );
      afterClosingStatus = afterClosing.status;
      release.resolve();
      const initialized = await firstInitialize;
      firstStatus = initialized.status;
      closeResult = await closing;
    } finally {
      release.resolve();
      gate.mockRestore();
      await app.closeMcpSessions();
    }

    expect(firstStatus).toBe(200);
    expect(afterClosingStatus).toBe(503);
    expect(closeResult).toBe(1);
  });

  test("synchronously closes a session at its original token expiry", async () => {
    let now = Date.now();
    await startApp({ mcpNow: () => now });
    const original = await issueAccessToken(client, "mail.read");
    const originalModel = await provider.AccessToken.find(original.accessToken);
    expect(originalModel?.exp).toBeTypeOf("number");
    const replacement = await mintAccessToken(
      original.accessToken,
      original.clientId,
      3_600,
    );
    const initialized = await mcpPost(
      original.accessToken,
      initializeRequest(),
    );
    const sessionId = initialized.headers["mcp-session-id"] as string;
    now = originalModel!.exp * 1_000;

    const response = await mcpPost(
      replacement,
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
      {
        "mcp-session-id": sessionId,
        "mcp-protocol-version": protocolVersion,
      },
    );

    expect(response.status).toBe(404);
  });

  test("synchronously closes a session after 30 minutes of inactivity", async () => {
    let now = Date.now();
    await startApp({ mcpNow: () => now });
    const issued = await issueAccessToken(client, "mail.read");
    const longLived = await mintAccessToken(
      issued.accessToken,
      issued.clientId,
      3_600,
    );
    const longLivedModel = await provider.AccessToken.find(longLived);
    expect(longLivedModel!.exp * 1_000).toBeGreaterThan(
      now + 30 * 60 * 1_000,
    );
    const initialized = await mcpPost(longLived, initializeRequest());
    const sessionId = initialized.headers["mcp-session-id"] as string;
    now += 30 * 60 * 1_000;

    const response = await mcpPost(
      longLived,
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
      {
        "mcp-session-id": sessionId,
        "mcp-protocol-version": protocolVersion,
      },
    );

    expect(response.status).toBe(404);
  });

  test("terminates a session when a different account tries to use it", async () => {
    const accountA = await issueAccessToken(client, "mail.read");
    const initialized = await mcpPost(accountA.accessToken, initializeRequest());
    const sessionId = initialized.headers["mcp-session-id"] as string;

    const accountBClient = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const accountB = await issueAccessToken(
      accountBClient,
      "mail.read",
      "other@example.test",
    );
    const rejected = await mcpPost(accountB.accessToken, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    }, {
      "mcp-session-id": sessionId,
      "mcp-protocol-version": protocolVersion,
    });
    expect(rejected.status).toBe(403);

    const terminated = await mcpPost(accountA.accessToken, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
      params: {},
    }, {
      "mcp-session-id": sessionId,
      "mcp-protocol-version": protocolVersion,
    });
    expect(terminated.status).toBe(404);
  });

  test("rejects a grant transplanted to another client before session dispatch", async () => {
    const account = await issueAccessToken(client, "mail.read");
    const accountToken = await provider.AccessToken.find(account.accessToken);
    expect(accountToken).toBeDefined();
    const initialized = await mcpPost(
      account.accessToken,
      initializeRequest(),
    );
    const sessionId = initialized.headers["mcp-session-id"] as string;

    const secondClientRegistration = await client.postJson("/oauth/reg", {
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    const secondClientId = (
      secondClientRegistration.json() as Record<string, unknown>
    ).client_id as string;
    const secondClient = await provider.Client.find(secondClientId);
    expect(secondClient).toBeDefined();
    const secondClientToken = await new provider.AccessToken({
      client: secondClient!,
      accountId: accountToken!.accountId,
      aud: resource.href,
      scope: "mail.read",
      grantId: accountToken!.grantId,
      gty: accountToken!.gty,
    }).save(900);

    const response = await mcpPost(
      secondClientToken,
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
      {
        "mcp-session-id": sessionId,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(response.status).toBe(401);

    const stillActive = await mcpPost(
      account.accessToken,
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/list",
        params: {},
      },
      {
        "mcp-session-id": sessionId,
        "mcp-protocol-version": protocolVersion,
      },
    );
    expect(stillActive.status).toBe(200);
  });

  test("refreshes the same grant after provider and application restart", async () => {
    const issued = await issueAccessToken(client, "mail.read");
    const original = await provider.AccessToken.find(issued.accessToken);
    expect(original?.grantId).toBeTypeOf("string");

    await restartProviderAndApp();
    const refreshed = await client.postForm("/oauth/token", {
      grant_type: "refresh_token",
      client_id: issued.clientId,
      refresh_token: issued.refreshToken,
      resource: resource.href,
    });
    expect(refreshed.status).toBe(200);
    const refreshedBody = refreshed.json() as Record<string, unknown>;
    expect(refreshedBody.access_token).toBeTypeOf("string");
    expect(refreshedBody.refresh_token).toBeTypeOf("string");
    expect(refreshedBody.refresh_token).not.toBe(issued.refreshToken);
    const refreshedModel = await provider.AccessToken.find(
      refreshedBody.access_token as string,
    );
    expect(refreshedModel?.grantId).toBe(original!.grantId);

    const initialized = await mcpPost(
      refreshedBody.access_token as string,
      initializeRequest(),
    );
    expect(initialized.status).toBe(200);
    expect(initialized.headers["mcp-session-id"]).toBeTypeOf("string");

    const reused = await client.postForm("/oauth/token", {
      grant_type: "refresh_token",
      client_id: issued.clientId,
      refresh_token: issued.refreshToken,
      resource: resource.href,
    });
    expect(reused.status).toBe(400);
    expect(reused.json()).toMatchObject({ error: "invalid_grant" });
  });
});
