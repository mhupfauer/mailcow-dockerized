import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Provider } from "oidc-provider";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi,
} from "vitest";

import { createApp } from "../../src/app.js";
import { MariaDbAccountRepository } from "../../src/auth/account-repository.js";
import {
  MariaDbAccountAuthorizationGate,
  MariaDbAccountAuthorizationRevoker,
  MariaDbConsentAuthorizationRepository,
} from "../../src/auth/authorization-state.js";
import type { CredentialVerifier } from "../../src/auth/credential-verifier.js";
import { AesGcmCredentialVault } from "../../src/auth/crypto-vault.js";
import { createOidcProvider } from "../../src/auth/oidc-provider.js";
import { initializeDatabase } from "../../src/db/init.js";
import { runMigrations } from "../../src/db/migrations.js";
import { createPool } from "../../src/db/pool.js";

const rootPassword = "root-password-for-interactions-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const databasePassword = "d".repeat(64);
const encryptionKey = Buffer.from(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  "hex",
);
const issuer = new URL("https://mail.example.test");
const resource = new URL("https://mail.example.test/mcp");
const redirectUri = "https://claude.ai/api/mcp/auth_callback";
const verifierValue = "v".repeat(64);
const challenge = createHash("sha256")
  .update(verifierValue, "ascii")
  .digest("base64url");

interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  json(): unknown;
}

interface ConsentRow extends RowDataPacket {
  scopes: string;
  revoked: number;
}

interface CountRow extends RowDataPacket {
  count: number;
}

function storedConsentScopes(raw: string | undefined): string[] {
  const parsed: unknown = JSON.parse(raw ?? "[]");
  if (Array.isArray(parsed)) {
    return parsed as string[];
  }
  return (parsed as { scopes?: string[] }).scopes ?? [];
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
    const cookie = [...this.cookies]
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

    return new Promise((resolve, reject) => {
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
            for (const value of response.headers["set-cookie"] ?? []) {
              const [pair] = value.split(";", 1);
              const separator = pair?.indexOf("=") ?? -1;
              if (pair !== undefined && separator > 0) {
                const name = pair.slice(0, separator);
                const cookieValue = pair.slice(separator + 1);
                if (cookieValue === "") {
                  this.cookies.delete(name);
                } else {
                  this.cookies.set(name, cookieValue);
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

  get(
    path: string,
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    return this.request(path, { headers });
  }

  postJson(path: string, body: unknown): Promise<HttpResponse> {
    return this.request(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  postForm(
    path: string,
    values: Record<string, string>,
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    return this.request(path, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...headers,
      },
      body: new URLSearchParams(values).toString(),
    });
  }
}

function hidden(html: string, name: string): string {
  const expression = new RegExp(
    `<input[^>]+name="${name}"[^>]+value="([^"]+)"`,
    "u",
  );
  const value = expression.exec(html)?.[1];
  expect(value).toBeTypeOf("string");
  return value as string;
}

function locationPath(response: HttpResponse): string {
  expect(response.status).toBe(303);
  expect(response.headers.location).toBeTypeOf("string");
  const target = new URL(response.headers.location as string, issuer);
  return `${target.pathname}${target.search}`;
}

function authPath(clientId: string, scope: string): string {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    resource: resource.href,
    scope,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return `/oauth/auth?${query.toString()}`;
}

describe("mailcow app-password interactions", () => {
  let container: StartedTestContainer;
  let pool: Pool;
  let provider: Provider;
  let client: HttpClient;
  let server: ReturnType<ReturnType<typeof createApp>["listen"]>;
  let protocolAttempts: Array<{ mailbox: string; password: string }>;
  let authenticationFailure: boolean;
  let verificationDelayMs: number;
  let verificationStarted: (() => void) | undefined;
  let accountRepository: MariaDbAccountRepository;
  let credentialVerifier: CredentialVerifier;

  beforeAll(async () => {
    container = await new GenericContainer("mariadb:10.11")
      .withEnvironment({ MARIADB_ROOT_PASSWORD: rootPassword })
      .withExposedPorts(3306)
      .start();
    const host = container.getHost();
    const port = container.getMappedPort(3306);
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
    await pool.query("DELETE FROM consents");
    await pool.query("DELETE FROM accounts");
    await pool.query("DELETE FROM service_state");
    protocolAttempts = [];
    authenticationFailure = false;
    verificationDelayMs = 0;
    verificationStarted = undefined;
    credentialVerifier = {
      async verify(mailbox, password) {
        protocolAttempts.push({ mailbox, password });
        verificationStarted?.();
        if (verificationDelayMs > 0) {
          await new Promise((resolve) =>
            setTimeout(resolve, verificationDelayMs),
          );
        }
        if (authenticationFailure) {
          throw new Error(`protocol rejected ${mailbox} ${password}`);
        }
      },
    };
    const vault = new AesGcmCredentialVault(encryptionKey);
    accountRepository = new MariaDbAccountRepository(pool, vault);
    provider = await createOidcProvider({
      pool,
      issuer,
      resource,
      encryptionKey,
    });
    await startApp();
  });

  async function startApp(
    overrides: {
      maximumInFlightInteractions?: number;
      maximumLoginQuotaEntries?: number;
      maximumConsentSessions?: number;
      maximumAuthorityMutations?: number;
      verificationTimeoutMs?: number;
    } = {},
  ): Promise<void> {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
    const app = createApp({
      readiness: async () => true,
      resourceMetadataUrl: new URL(
        "/.well-known/oauth-protected-resource/mcp",
        issuer,
      ),
      oidcProvider: provider,
      interactions: {
        accountRepository,
        credentialVerifier,
        pool,
        issuer,
        resource,
        encryptionKey,
        loginAttempts: 5,
        loginWindowSeconds: 900,
        ...overrides,
      },
    });
    server = app.listen(0);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    client = new HttpClient((server.address() as AddressInfo).port);
  }

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  async function registerClient(): Promise<string> {
    const response = await client.postJson("/oauth/reg", {
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    expect(response.status).toBe(201);
    const body = response.json() as Record<string, unknown>;
    expect(body.client_id).toBeTypeOf("string");
    return body.client_id as string;
  }

  async function loginPage(
    clientId: string,
    scope = "mail.read",
  ): Promise<{ path: string; response: HttpResponse }> {
    const start = await client.get(authPath(clientId, scope));
    const path = locationPath(start);
    expect(path).toMatch(/^\/mcp-login\/[A-Za-z0-9_-]+$/u);
    const response = await client.get(path);
    expect(response.status).toBe(200);
    return { path, response };
  }

  async function loginPageFor(
    targetClient: HttpClient,
    clientId: string,
    scope = "mail.read",
  ): Promise<{ path: string; response: HttpResponse }> {
    const start = await targetClient.get(authPath(clientId, scope));
    const path = locationPath(start);
    expect(path).toMatch(/^\/mcp-login\/[A-Za-z0-9_-]+$/u);
    const response = await targetClient.get(path);
    expect(response.status).toBe(200);
    return { path, response };
  }

  async function submitLogin(
    path: string,
    page: HttpResponse,
    mailbox = "user@example.test",
    password = "app-password",
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    return client.postForm(
      path,
      {
        csrf: hidden(page.body, "csrf"),
        mailbox,
        app_password: password,
      },
      headers,
    );
  }

  async function reachConsent(
    loginResponse: HttpResponse,
  ): Promise<{ path: string; response: HttpResponse }> {
    const resume = await client.get(locationPath(loginResponse));
    const path = locationPath(resume);
    expect(path).toMatch(/^\/mcp-login\/[A-Za-z0-9_-]+$/u);
    const response = await client.get(path);
    expect(response.status).toBe(200);
    return { path, response };
  }

  async function reachConsentFor(
    targetClient: HttpClient,
    loginResponse: HttpResponse,
  ): Promise<{ path: string; response: HttpResponse }> {
    const resume = await targetClient.get(locationPath(loginResponse));
    const path = locationPath(resume);
    expect(path).toMatch(/^\/mcp-login\/[A-Za-z0-9_-]+$/u);
    const response = await targetClient.get(path);
    expect(response.status).toBe(200);
    return { path, response };
  }

  async function distinctLoginPages(
    clientId: string,
    count: number,
  ): Promise<
    Array<{ client: HttpClient; path: string; response: HttpResponse }>
  > {
    const port = (server.address() as AddressInfo).port;
    return Promise.all(
      Array.from({ length: count }, async () => {
        const distinctClient = new HttpClient(port);
        const login = await loginPageFor(distinctClient, clientId);
        return { client: distinctClient, ...login };
      }),
    );
  }

  test("renders a secret-free login and completes both-protocol authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    expect(login.response.headers["content-security-policy"]).toContain(
      "default-src 'none'",
    );
    expect(login.response.headers["cache-control"]).toContain("no-store");
    expect(login.response.body).toContain("dedicated mailcow app password");
    expect(login.response.body).toContain("IMAP and SMTP");
    expect(login.response.body).toContain(
      "cannot distinguish it from your primary password",
    );
    const cookies = login.response.headers["set-cookie"] ?? [];
    expect(cookies).toHaveLength(1);
    expect(cookies[0]).toMatch(
      /^mailcow_mcp_interaction_csrf=[^;]+; Path=\/mcp-login; HttpOnly; Secure; SameSite=Lax$/u,
    );

    const submitted = await submitLogin(
      login.path,
      login.response,
      "User@EXAMPLE.TEST",
      "a<&secret-password",
    );

    expect(submitted.status).toBe(303);
    expect(protocolAttempts).toEqual([
      {
        mailbox: "User@example.test",
        password: "a<&secret-password",
      },
    ]);
    expect(login.response.body).not.toContain("a<&secret-password");
    expect(submitted.body).not.toContain("a<&secret-password");
  });

  test("rejects CSRF and protocol failures with generic secret-free responses", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    const csrfRejected = await client.postForm(login.path, {
      csrf: "tampered",
      mailbox: "user@example.test",
      app_password: "csrf-secret",
    });
    expect(csrfRejected.status).toBe(403);
    expect(csrfRejected.headers["cache-control"]).toContain("no-store");
    expect(protocolAttempts).toHaveLength(0);

    authenticationFailure = true;
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "authentication-secret",
    );
    expect(rejected.status).toBe(401);
    expect(rejected.body).toContain("Authentication failed");
    const observable = `${rejected.body}\n${JSON.stringify(errorSpy.mock.calls)}`;
    expect(observable).not.toContain("authentication-secret");
    expect(observable).not.toContain("protocol rejected");
    errorSpy.mockRestore();
  });

  test("blocks the sixth failure by source IP before rotating mailbox attempts", async () => {
    authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "x-forwarded-for": "198.51.100.10, 203.0.113.50",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        `user${attempt}@example.test`,
        "bad-password",
        forwarded,
      );
      expect(response.status).toBe(401);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "another@example.test",
      "bad-password",
      forwarded,
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(5);
  });

  test("blocks the sixth failure by canonical mailbox across rotating IPs", async () => {
    authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        attempt % 2 === 0 ? "USER@EXAMPLE.TEST" : "user@example.test",
        "bad-password",
        {
          "x-forwarded-for": `198.51.100.10, 203.0.113.${attempt}`,
        },
      );
      expect(response.status).toBe(401);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "User@example.test",
      "bad-password",
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.99",
      },
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(5);
  });

  test("atomically caps concurrent protocol verification by source IP across distinct interactions", async () => {
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 6);
    verificationDelayMs = 200;

    const firstFive = logins
      .slice(0, 5)
      .map(({ client: loginClient, path, response }, index) =>
        loginClient.postForm(
          path,
          {
            csrf: hidden(response.body, "csrf"),
            mailbox: `user${index}@example.test`,
            app_password: "app-password",
          },
          {
            "x-forwarded-for": "198.51.100.10, 203.0.113.80",
          },
        ),
      );
    await new Promise<void>((resolve) => {
      if (protocolAttempts.length === 5) {
        resolve();
        return;
      }
      verificationStarted = () => {
        if (protocolAttempts.length === 5) {
          resolve();
        }
      };
    });
    const sixth = logins[5]!;
    const rejected = await sixth.client.postForm(
      sixth.path,
      {
        csrf: hidden(sixth.response.body, "csrf"),
        mailbox: "user5@example.test",
        app_password: "app-password",
      },
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.80",
      },
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(5);
    expect(
      (await Promise.all(firstFive)).map((response) => response.status),
    ).toEqual([303, 303, 303, 303, 303]);
  });

  test("atomically caps concurrent protocol verification by mailbox across distinct IPs", async () => {
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 6);
    verificationDelayMs = 200;

    const firstFive = logins
      .slice(0, 5)
      .map(({ client: loginClient, path, response }, index) =>
        loginClient.postForm(
          path,
          {
            csrf: hidden(response.body, "csrf"),
            mailbox:
              index % 2 === 0 ? "USER@EXAMPLE.TEST" : "user@example.test",
            app_password: "app-password",
          },
          {
            "x-forwarded-for": `198.51.100.10, 203.0.113.${90 + index}`,
          },
        ),
      );
    await new Promise<void>((resolve) => {
      if (protocolAttempts.length === 5) {
        resolve();
        return;
      }
      verificationStarted = () => {
        if (protocolAttempts.length === 5) {
          resolve();
        }
      };
    });
    const sixth = logins[5]!;
    const rejected = await sixth.client.postForm(
      sixth.path,
      {
        csrf: hidden(sixth.response.body, "csrf"),
        mailbox: "User@example.test",
        app_password: "app-password",
      },
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.99",
      },
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(5);
    expect(
      (await Promise.all(firstFive)).map((response) => response.status),
    ).toEqual([303, 303, 303, 303, 303]);
  });

  test("fails closed when the bounded interaction lock is full", async () => {
    await startApp({ maximumInFlightInteractions: 1 });
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 2);
    verificationDelayMs = 200;
    const started = new Promise<void>((resolve) => {
      verificationStarted = resolve;
    });
    const first = logins[0]!.client.postForm(logins[0]!.path, {
      csrf: hidden(logins[0]!.response.body, "csrf"),
      mailbox: "first@example.test",
      app_password: "app-password",
    });
    await started;
    const rejected = await logins[1]!.client.postForm(logins[1]!.path, {
      csrf: hidden(logins[1]!.response.body, "csrf"),
      mailbox: "second@example.test",
      app_password: "app-password",
    });

    expect(rejected.status).toBe(503);
    expect(protocolAttempts).toHaveLength(1);
    expect((await first).status).toBe(303);
  });

  test("times out protocol verification and releases the interaction lock", async () => {
    await startApp({ verificationTimeoutMs: 25 });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    verificationDelayMs = 100;

    const timedOut = await submitLogin(login.path, login.response);
    expect(timedOut.status).toBe(401);

    verificationDelayMs = 0;
    const retried = await submitLogin(login.path, login.response);
    expect(retried.status).toBe(303);
    expect(protocolAttempts).toHaveLength(2);
  });

  test("does not poison authentication quotas after repository failures", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const originalUpsert =
      accountRepository.upsertVerified.bind(accountRepository);
    let failures = 0;
    const upsert = vi
      .spyOn(accountRepository, "upsertVerified")
      .mockImplementation(async (mailbox, password) => {
        if (failures < 5) {
          failures += 1;
          throw new Error(`database rejected ${mailbox} ${password}`);
        }
        return originalUpsert(mailbox, password);
      });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        "user@example.test",
        "operational-secret",
      );
      expect(response.status).toBe(503);
      expect(response.headers["cache-control"]).toContain("no-store");
      expect(response.body).not.toContain("database rejected");
      expect(response.body).not.toContain("operational-secret");
    }
    const succeeded = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
    );

    expect(succeeded.status).toBe(303);
    expect(protocolAttempts).toHaveLength(6);
    upsert.mockRestore();
  });

  test("does not poison authentication quotas after provider failures", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const originalFinished = provider.interactionFinished.bind(provider);
    let failures = 0;
    const finished = vi
      .spyOn(provider, "interactionFinished")
      .mockImplementation(async (...args) => {
        if (failures < 5) {
          failures += 1;
          throw new Error("provider unavailable");
        }
        return originalFinished(...args);
      });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        "user@example.test",
        "operational-secret",
      );
      expect(response.status).toBe(503);
      expect(response.headers["cache-control"]).toContain("no-store");
      expect(response.body).not.toContain("provider unavailable");
      expect(response.body).not.toContain("operational-secret");
    }
    const succeeded = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
    );

    expect(succeeded.status).toBe(303);
    expect(protocolAttempts).toHaveLength(6);
    finished.mockRestore();
  });

  test("fails closed when the bounded login quota map is full", async () => {
    await startApp({ maximumLoginQuotaEntries: 1 });
    authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    const failed = await submitLogin(
      login.path,
      login.response,
      "first@example.test",
      "bad-password",
      { "x-forwarded-for": "198.51.100.1" },
    );
    expect(failed.status).toBe(401);

    const rejected = await submitLogin(
      login.path,
      login.response,
      "second@example.test",
      "bad-password",
      { "x-forwarded-for": "198.51.100.2" },
    );
    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(1);
  });

  test("counts oversized login bodies against the source quota before authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "content-type": "application/x-www-form-urlencoded",
      "x-forwarded-for": "198.51.100.10, 203.0.113.70",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await client.request(login.path, {
        method: "POST",
        headers: forwarded,
        body: `padding=${"x".repeat(20 * 1_024)}`,
      });
      expect(response.status).toBe(413);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
      forwarded,
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(0);
  });

  test("counts malformed login bodies against the source quota before authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "content-type": "application/json",
      "x-forwarded-for": "198.51.100.10, 203.0.113.71",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await client.request(login.path, {
        method: "POST",
        headers: forwarded,
        body: "{",
      });
      expect(response.status).toBe(403);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
      {
        "x-forwarded-for": forwarded["x-forwarded-for"],
      },
    );

    expect(rejected.status).toBe(429);
    expect(protocolAttempts).toHaveLength(0);
  });

  test("bounds consent, reuses it, expands only after prompting, and revokes it explicitly", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    expect(consent.response.body).toContain("mail.read");
    expect(consent.response.body).not.toContain("mail.send");

    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
      scopes: "mail.read mail.send administrator",
    });
    expect(approved.status).toBe(303);
    const [consents] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(consents[0]?.scopes)).toEqual(["mail.read"]);
    expect(consents[0]?.revoked).toBe(0);

    const callback = await client.get(locationPath(approved));
    const callbackUrl = new URL(callback.headers.location as string);
    expect(callbackUrl.origin).toBe(new URL(redirectUri).origin);
    const authorizationCode = await provider.AuthorizationCode.find(
      callbackUrl.searchParams.get("code") as string,
    );
    const grantId = authorizationCode?.grantId;
    expect(grantId).toBeTypeOf("string");
    const grant = await provider.Grant.find(grantId as string);
    expect(grant?.getResourceScope(resource.href)).toBe("mail.read");
    const token = await client.postForm("/oauth/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code: callbackUrl.searchParams.get("code") as string,
      code_verifier: verifierValue,
      resource: resource.href,
    });
    expect(token.status).toBe(200);
    const tokenBody = token.json() as Record<string, unknown>;
    expect(tokenBody.access_token).toBeTypeOf("string");
    expect(tokenBody.refresh_token).toBeTypeOf("string");

    const reused = await client.get(authPath(clientId, "mail.read"));
    expect(new URL(reused.headers.location as string).origin).toBe(
      new URL(redirectUri).origin,
    );

    const expansionStart = await client.get(
      authPath(clientId, "mail.read mail.send"),
    );
    const expansionPath = locationPath(expansionStart);
    expect(expansionPath).toMatch(/^\/mcp-login\//u);
    const expansion = await client.get(expansionPath);
    expect(expansion.body).toContain("mail.send");

    const expanded = await client.postForm(expansionPath, {
      csrf: hidden(expansion.body, "csrf"),
      decision: "approve",
    });
    expect(expanded.status).toBe(303);
    await client.get(locationPath(expanded));
    const [expandedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(expandedRows[0]?.scopes)).toEqual([
      "mail.read",
      "mail.send",
    ]);

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const narrowerReuse = await freshSession.get(freshConsentPath);
    expect(narrowerReuse.status).toBe(303);
    const freshCallback = await freshSession.get(locationPath(narrowerReuse));
    const freshCallbackUrl = new URL(freshCallback.headers.location as string);
    const freshCode = freshCallbackUrl.searchParams.get("code");
    expect(freshCode).toBeTypeOf("string");
    const freshAuthorizationCode = await provider.AuthorizationCode.find(
      freshCode as string,
    );
    expect(freshAuthorizationCode?.grantId).toBe(grantId);
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(1);
    const [preservedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(storedConsentScopes(preservedRows[0]?.scopes)).toEqual([
      "mail.read",
      "mail.send",
    ]);
    const rawConsent = preservedRows[0]?.scopes ?? "";
    expect(rawConsent).not.toContain(grantId as string);
    const parsedConsent = JSON.parse(rawConsent) as Record<string, unknown>;
    expect(parsedConsent.authorityEnvelope).toBeTypeOf("string");
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
    const accountId = authorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const authorizationState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(authorizationState?.reusable).toBe(true);
    expect(authorizationState?.sessionIds.length).toBeGreaterThan(0);
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(rawConsent).not.toContain(sessionId);
    }

    const revocationStart = await client.get(
      authPath(clientId, "mail.read mail.send mail.organize"),
    );
    const revocationPath = locationPath(revocationStart);
    const revocation = await client.get(revocationPath);
    expect(revocation.body).toContain("mail.organize");
    const revokeForm = {
      csrf: hidden(revocation.body, "csrf"),
      decision: "revoke",
    };
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("provider unavailable"));
    const originalInteractionResult = provider.interactionResult.bind(provider);
    let stagedReturnTo: string | undefined;
    const interactionResult = vi
      .spyOn(provider, "interactionResult")
      .mockImplementation(async (...args) => {
        stagedReturnTo = await originalInteractionResult(...args);
        return stagedReturnTo;
      });
    const unavailable = await client.postForm(revocationPath, revokeForm);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers["cache-control"]).toContain("no-store");
    expect(unavailable.body).not.toContain("provider unavailable");
    expect(await provider.Grant.find(grantId as string)).toBeDefined();
    const [retryRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(retryRows[0]?.revoked).toBe(0);
    expect(retryRows[0]?.scopes).toBe(rawConsent);
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
    revokeAccessToken.mockRestore();

    const revoked = await client.postForm(revocationPath, revokeForm);
    expect(revoked.status).toBe(303);
    expect(revoked.headers["content-length"]).toBe("0");
    expect(revoked.headers.location).toBe(stagedReturnTo);
    interactionResult.mockRestore();
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(freshCode as string),
    ).toBeUndefined();
    expect(
      await provider.AccessToken.find(tokenBody.access_token as string),
    ).toBeUndefined();
    expect(
      await provider.RefreshToken.find(tokenBody.refresh_token as string),
    ).toBeUndefined();
    const [remainingGrants] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(remainingGrants[0]?.count).toBe(0);
    const [revokedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(revokedRows[0]?.revoked).toBe(1);
    for (const sessionId of authorizationState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }

    await client.get(locationPath(revoked));
    const afterRevocation = await client.get(authPath(clientId, "mail.read"));
    const afterRevocationPath = locationPath(afterRevocation);
    expect(afterRevocationPath).toMatch(/^\/mcp-login\//u);
  });

  test("serializes parallel first approvals onto one canonical grant", async () => {
    const clientId = await registerClient();
    const port = (server.address() as AddressInfo).port;
    const firstClient = new HttpClient(port);
    const secondClient = new HttpClient(port);
    const firstLogin = await loginPageFor(firstClient, clientId);
    const secondLogin = await loginPageFor(secondClient, clientId);
    const firstLoggedIn = await firstClient.postForm(firstLogin.path, {
      csrf: hidden(firstLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const firstConsent = await reachConsentFor(firstClient, firstLoggedIn);
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const originalSave = provider.Grant.prototype.save;
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return originalSave.apply(this, args);
      });

    const [firstApproved, secondApproved] = await Promise.all([
      firstClient.postForm(firstConsent.path, {
        csrf: hidden(firstConsent.response.body, "csrf"),
        decision: "approve",
      }),
      secondClient.postForm(secondConsent.path, {
        csrf: hidden(secondConsent.response.body, "csrf"),
        decision: "approve",
      }),
    ]);
    save.mockRestore();

    expect(firstApproved.status).toBe(303);
    expect(secondApproved.status).toBe(303);
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(1);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(2);
    const firstCallback = await firstClient.get(locationPath(firstApproved));
    const firstCode = new URL(
      firstCallback.headers.location as string,
    ).searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      firstCode as string,
    );
    const state = await new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    ).getActive(authorizationCode?.accountId as string, clientId);
    expect(state?.sessionIds).toHaveLength(2);
    const [rawRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const raw = rawRows[0]?.scopes ?? "";
    expect(raw).not.toContain(authorizationCode?.grantId as string);
    for (const sessionId of state?.sessionIds ?? []) {
      expect(raw).not.toContain(sessionId);
    }
  });

  test("fails closed when the bounded authority mutation lock is full", async () => {
    await startApp({ maximumAuthorityMutations: 1 });
    const firstClientId = await registerClient();
    const secondClientId = await registerClient();
    const port = (server.address() as AddressInfo).port;
    const firstClient = new HttpClient(port);
    const secondClient = new HttpClient(port);
    const firstLogin = await loginPageFor(firstClient, firstClientId);
    const secondLogin = await loginPageFor(secondClient, secondClientId);
    const firstLoggedIn = await firstClient.postForm(firstLogin.path, {
      csrf: hidden(firstLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const secondLoggedIn = await secondClient.postForm(secondLogin.path, {
      csrf: hidden(secondLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const firstConsent = await reachConsentFor(firstClient, firstLoggedIn);
    const secondConsent = await reachConsentFor(secondClient, secondLoggedIn);
    const originalSave = provider.Grant.prototype.save;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let grantSaved!: () => void;
    const saved = new Promise<void>((resolve) => {
      grantSaved = resolve;
    });
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        const grantId = await originalSave.apply(this, args);
        grantSaved();
        await waiting;
        return grantId;
      });
    const firstApproval = firstClient.postForm(firstConsent.path, {
      csrf: hidden(firstConsent.response.body, "csrf"),
      decision: "approve",
    });
    await saved;
    const rejected = await secondClient.postForm(secondConsent.path, {
      csrf: hidden(secondConsent.response.body, "csrf"),
      decision: "approve",
    });
    releaseSave();
    const approved = await firstApproval;
    save.mockRestore();

    expect(rejected.status).toBe(503);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    expect(approved.status).toBe(303);
  });

  test("serializes concurrent session-cap updates without forgetting a live session", async () => {
    await startApp({ maximumConsentSessions: 2 });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const code = new URL(callback.headers.location as string).searchParams.get(
      "code",
    );
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId as string;

    const port = (server.address() as AddressInfo).port;
    const freshClients = [new HttpClient(port), new HttpClient(port)];
    const consentPages = await Promise.all(
      freshClients.map(async (freshClient) => {
        const freshLogin = await loginPageFor(freshClient, clientId);
        const freshLoggedIn = await freshClient.postForm(freshLogin.path, {
          csrf: hidden(freshLogin.response.body, "csrf"),
          mailbox: "user@example.test",
          app_password: "app-password",
        });
        const resume = await freshClient.get(locationPath(freshLoggedIn));
        const path = locationPath(resume);
        const response = await freshClient.get(path);
        return { freshClient, response };
      }),
    );
    expect(consentPages.map(({ response }) => response.status)).toEqual([
      303, 303,
    ]);
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
    const state = await consentRepository.getActive(accountId, clientId);
    expect(state?.sessionIds).toHaveLength(2);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(2);
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
  });

  test("refuses consent when the account is revoked between read and transactional save", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const originalSave = provider.Grant.prototype.save;
    let releaseSave!: () => void;
    const waiting = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let grantSaved!: () => void;
    const saved = new Promise<void>((resolve) => {
      grantSaved = resolve;
    });
    const save = vi
      .spyOn(provider.Grant.prototype, "save")
      .mockImplementation(async function (...args) {
        const grantId = await originalSave.apply(this, args);
        grantSaved();
        await waiting;
        return grantId;
      });
    const approval = client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    await saved;
    const [accountRows] = await pool.query<
      Array<RowDataPacket & { accountId: string }>
    >(
      `SELECT LOWER(CONCAT(
         SUBSTR(HEX(id), 1, 8), '-',
         SUBSTR(HEX(id), 9, 4), '-',
         SUBSTR(HEX(id), 13, 4), '-',
         SUBSTR(HEX(id), 17, 4), '-',
         SUBSTR(HEX(id), 21)
       )) AS accountId
       FROM accounts`,
    );
    const accountId = accountRows[0]?.accountId;
    expect(accountId).toBeTypeOf("string");
    await accountRepository.markCredentialRejected(accountId as string);
    releaseSave();
    const rejected = await approval;
    save.mockRestore();

    expect(rejected.status).toBe(401);
    expect(rejected.headers["cache-control"]).toContain("no-store");
    const [grantRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Grant'`,
    );
    expect(grantRows[0]?.count).toBe(0);
    const [sessionRows] = await pool.query<CountRow[]>(
      `SELECT COUNT(*) AS count FROM oidc_objects WHERE model = 'Session'`,
    );
    expect(sessionRows[0]?.count).toBe(0);
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId as string,
      ),
    ).toBe(false);
    const oldSession = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(oldSession)).toMatch(/^\/mcp-login\//u);

    const reauthenticated = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const reauthLogin = await loginPageFor(reauthenticated, clientId);
    const reauthLoggedIn = await reauthenticated.postForm(reauthLogin.path, {
      csrf: hidden(reauthLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const reauthConsent = await reachConsentFor(
      reauthenticated,
      reauthLoggedIn,
    );
    const reapproved = await reauthenticated.postForm(reauthConsent.path, {
      csrf: hidden(reauthConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(reapproved.status).toBe(303);
  });

  test("quarantines legacy consent until credential reauthentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    await client.get(locationPath(approved));
    await pool.execute(`UPDATE consents SET scopes = JSON_ARRAY('mail.read')`);

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const freshConsent = await freshSession.get(freshConsentPath);

    expect(freshConsent.status).toBe(401);
    const [quarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(quarantinedRows[0]?.scopes).toBe('["mail.read"]');
    expect(quarantinedRows[0]?.revoked).toBe(1);
    const [accountRows] = await pool.query<
      Array<RowDataPacket & { accountId: string }>
    >(
      `SELECT LOWER(CONCAT(
         SUBSTR(HEX(id), 1, 8), '-',
         SUBSTR(HEX(id), 9, 4), '-',
         SUBSTR(HEX(id), 13, 4), '-',
         SUBSTR(HEX(id), 17, 4), '-',
         SUBSTR(HEX(id), 21)
       )) AS accountId
       FROM accounts`,
    );
    const accountId = accountRows[0]?.accountId;
    expect(accountId).toBeTypeOf("string");
    expect(
      await accountRepository.getCredential(accountId as string),
    ).toBeNull();
    expect(
      await new MariaDbAccountAuthorizationGate(pool).isAccountActive(
        accountId as string,
      ),
    ).toBe(false);
    const oldSessionRetry = await freshSession.get(
      authPath(clientId, "mail.read"),
    );
    expect(locationPath(oldSessionRetry)).toMatch(/^\/mcp-login\//u);

    const reauthenticated = new HttpClient(
      (server.address() as AddressInfo).port,
    );
    const reauthLogin = await loginPageFor(
      reauthenticated,
      clientId,
      "mail.read",
    );
    const reauthLoggedIn = await reauthenticated.postForm(reauthLogin.path, {
      csrf: hidden(reauthLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const reauthConsent = await reachConsentFor(
      reauthenticated,
      reauthLoggedIn,
    );
    const reapproved = await reauthenticated.postForm(reauthConsent.path, {
      csrf: hidden(reauthConsent.response.body, "csrf"),
      decision: "approve",
    });
    expect(reapproved.status).toBe(303);
    const [repairedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(repairedRows[0]?.revoked).toBe(0);
    expect(JSON.parse(repairedRows[0]?.scopes ?? "{}")).toHaveProperty(
      "authorityEnvelope",
    );
  });

  test("quarantines tampered authority without overwriting unknown state", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    expect(approved.status).toBe(303);
    await client.get(locationPath(approved));
    await pool.execute(
      `UPDATE consents
       SET scopes = JSON_SET(scopes, '$.authorityEnvelope', 'tampered')`,
    );
    const [tamperedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    const tamperedRaw = tamperedRows[0]?.scopes;

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshStart = await freshSession.get(authPath(clientId, "mail.read"));
    const freshLoginPath = locationPath(freshStart);
    const freshLogin = await freshSession.get(freshLoginPath);
    const freshLoggedIn = await freshSession.postForm(freshLoginPath, {
      csrf: hidden(freshLogin.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const freshConsent = await freshSession.get(freshConsentPath);

    expect(freshConsent.status).toBe(401);
    expect(freshConsent.body).not.toContain("tampered");
    const [quarantinedRows] = await pool.query<ConsentRow[]>(
      `SELECT CAST(scopes AS CHAR) AS scopes, revoked_at IS NOT NULL AS revoked
       FROM consents`,
    );
    expect(quarantinedRows[0]?.scopes).toBe(tamperedRaw);
    expect(quarantinedRows[0]?.revoked).toBe(1);
  });

  test("bounds remembered consent sessions and destroys the evicted provider session", async () => {
    await startApp({ maximumConsentSessions: 2 });
    const clientId = await registerClient();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const firstCode = new URL(
      callback.headers.location as string,
    ).searchParams.get("code");
    const firstAuthorizationCode = await provider.AuthorizationCode.find(
      firstCode as string,
    );
    const accountId = firstAuthorizationCode?.accountId;
    expect(accountId).toBeTypeOf("string");
    const firstState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    const firstSessionId = firstState?.sessionIds[0];
    expect(firstSessionId).toBeTypeOf("string");

    for (let index = 0; index < 2; index += 1) {
      const freshSession = new HttpClient(
        (server.address() as AddressInfo).port,
      );
      const freshLogin = await loginPageFor(
        freshSession,
        clientId,
        "mail.read",
      );
      const freshLoggedIn = await freshSession.postForm(freshLogin.path, {
        csrf: hidden(freshLogin.response.body, "csrf"),
        mailbox: "user@example.test",
        app_password: "app-password",
      });
      const freshResume = await freshSession.get(locationPath(freshLoggedIn));
      const freshConsentPath = locationPath(freshResume);
      const reused = await freshSession.get(freshConsentPath);
      expect(reused.status).toBe(303);
      await freshSession.get(locationPath(reused));
    }

    const boundedState = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(boundedState?.sessionIds).toHaveLength(2);
    expect(boundedState?.sessionIds).not.toContain(firstSessionId);
    expect(
      await provider.Session.findByUid(firstSessionId as string),
    ).toBeUndefined();
    for (const sessionId of boundedState?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeDefined();
    }
  });

  test("revokes account credentials, consent, grants, tokens, codes, and sessions together", async () => {
    const clientId = await registerClient();
    const consentRepository = new MariaDbConsentAuthorizationRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
    const login = await loginPage(clientId, "mail.read");
    const loggedIn = await submitLogin(login.path, login.response);
    const consent = await reachConsent(loggedIn);
    const approved = await client.postForm(consent.path, {
      csrf: hidden(consent.response.body, "csrf"),
      decision: "approve",
    });
    const callback = await client.get(locationPath(approved));
    const callbackUrl = new URL(callback.headers.location as string);
    const code = callbackUrl.searchParams.get("code");
    const authorizationCode = await provider.AuthorizationCode.find(
      code as string,
    );
    const accountId = authorizationCode?.accountId;
    const grantId = authorizationCode?.grantId;
    expect(accountId).toBeTypeOf("string");
    expect(grantId).toBeTypeOf("string");
    const token = await client.postForm("/oauth/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code: code as string,
      code_verifier: verifierValue,
      resource: resource.href,
    });
    expect(token.status).toBe(200);
    const tokenBody = token.json() as Record<string, unknown>;

    const freshSession = new HttpClient((server.address() as AddressInfo).port);
    const freshLogin = await loginPageFor(freshSession, clientId, "mail.read");
    const freshLoggedIn = await freshSession.postForm(freshLogin.path, {
      csrf: hidden(freshLogin.response.body, "csrf"),
      mailbox: "user@example.test",
      app_password: "app-password",
    });
    const freshResume = await freshSession.get(locationPath(freshLoggedIn));
    const freshConsentPath = locationPath(freshResume);
    const reused = await freshSession.get(freshConsentPath);
    const freshCallback = await freshSession.get(locationPath(reused));
    const freshCode = new URL(
      freshCallback.headers.location as string,
    ).searchParams.get("code");
    const state = await consentRepository.getActive(
      accountId as string,
      clientId,
    );
    expect(state?.sessionIds).toHaveLength(2);

    const revoker = new MariaDbAccountAuthorizationRevoker(
      accountRepository,
      consentRepository,
      provider,
    );
    const revokeAccessToken = vi
      .spyOn(provider.AccessToken, "revokeByGrantId")
      .mockRejectedValueOnce(new Error("provider unavailable"));
    await expect(
      revoker.revokeCredential(accountId as string),
    ).rejects.toThrow();
    const authorizationGate = new MariaDbAccountAuthorizationGate(pool);
    expect(await authorizationGate.isAccountActive(accountId as string)).toBe(
      false,
    );
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    const survivingSession = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(survivingSession)).toMatch(/^\/mcp-login\//u);
    revokeAccessToken.mockRestore();
    await revoker.revokeCredential(accountId as string);

    expect(
      await accountRepository.getCredential(accountId as string),
    ).toBeNull();
    expect(
      await consentRepository.getActive(accountId as string, clientId),
    ).toBeNull();
    expect(await provider.Grant.find(grantId as string)).toBeUndefined();
    expect(
      await provider.AuthorizationCode.find(freshCode as string),
    ).toBeUndefined();
    expect(
      await provider.AccessToken.find(tokenBody.access_token as string),
    ).toBeUndefined();
    expect(
      await provider.RefreshToken.find(tokenBody.refresh_token as string),
    ).toBeUndefined();
    for (const sessionId of state?.sessionIds ?? []) {
      expect(await provider.Session.findByUid(sessionId)).toBeUndefined();
    }
    const afterRevocation = await client.get(authPath(clientId, "mail.read"));
    expect(locationPath(afterRevocation)).toMatch(/^\/mcp-login\//u);
  });

  test("rejects a provider interaction with an unallowlisted return URL", async () => {
    const details = provider.interactionDetails.bind(provider);
    vi.spyOn(provider, "interactionDetails").mockImplementationOnce(
      async (request, response) => ({
        ...(await details(request, response)),
        returnTo: "https://evil.example/oauth/resume",
      }),
    );
    const clientId = await registerClient();
    const started = await client.get(authPath(clientId, "mail.read"));
    const response = await client.get(locationPath(started));

    expect(response.status).toBe(400);
    expect(response.body).not.toContain("evil.example");
  });

  test("allows only one parallel login submission for an interaction", async () => {
    let release: (() => void) | undefined;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const startedVerification = new Promise<void>((resolve) => {
      const original = protocolAttempts.push.bind(protocolAttempts);
      protocolAttempts.push = (...values) => {
        const result = original(...values);
        resolve();
        return result;
      };
    });
    authenticationFailure = false;
    const originalVerifier = provider;
    void originalVerifier;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    // Delay the repository path without changing the external protocol fake.
    const execute = pool.execute.bind(pool);
    const executeSpy = vi
      .spyOn(pool, "execute")
      .mockImplementation(async (...args: Parameters<typeof pool.execute>) => {
        if (
          typeof args[0] === "string" &&
          args[0].includes("INSERT INTO accounts")
        ) {
          await waiting;
        }
        return execute(...args);
      });
    const first = submitLogin(login.path, login.response);
    await startedVerification;
    const duplicate = await submitLogin(login.path, login.response);
    release?.();
    const [firstResponse, duplicateResponse] = await Promise.all([
      first,
      duplicate,
    ]);

    expect([firstResponse.status, duplicateResponse.status].sort()).toEqual([
      303, 409,
    ]);
    executeSpy.mockRestore();
  });
});
