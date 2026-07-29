import type { AddressInfo } from "node:net";

import { describe, expect, test } from "vitest";

import {
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
  server,
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
): Promise<{ accessToken: string; clientId: string }> {
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
  return { accessToken: body.access_token as string, clientId };
}

async function mcpPost(
  bearer: string | undefined,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return client.request("/mcp", {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }),
      ...headers,
    },
    body: JSON.stringify(body),
  });
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
});
