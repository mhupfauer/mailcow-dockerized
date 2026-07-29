import type { AddressInfo } from "node:net";

import { describe, expect, test } from "vitest";

import {
  app,
  client,
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

describe("protected MCP Streamable HTTP", () => {
  installInteractionsFixture();

  test("publishes exact protected-resource metadata", async () => {
    const response = await client.get(
      "/.well-known/oauth-protected-resource/mcp",
    );

    expect(response.status).toBe(200);
    expect(response.json()).toEqual({
      resource: resource.href,
      authorization_servers: [issuer.href],
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

  test("rejects a bearer token that lacks mail.read", async () => {
    const issued = await issueAccessToken(client, "mail.send");

    const response = await mcpPost(issued.accessToken, initializeRequest());

    expect(response.status).toBe(403);
    expect(response.headers["www-authenticate"]).toContain(
      'error="insufficient_scope"',
    );
    expect(response.headers["www-authenticate"]).toContain('scope="mail.read"');
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

  test("terminates a session when a different client for the same account uses it", async () => {
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
    expect(response.status).toBe(403);
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
  });
});
