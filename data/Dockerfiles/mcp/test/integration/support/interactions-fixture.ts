import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Provider } from "oidc-provider";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, afterEach, beforeAll, beforeEach, expect } from "vitest";

import { createApp } from "../../../src/app.js";
import { MariaDbAccountRepository } from "../../../src/auth/account-repository.js";
import { BoundedAuthorizationMutationCoordinator } from "../../../src/auth/authorization-state.js";
import type { CredentialVerifier } from "../../../src/auth/credential-verifier.js";
import { AesGcmCredentialVault } from "../../../src/auth/crypto-vault.js";
import { createOidcProvider } from "../../../src/auth/oidc-provider.js";
import { initializeDatabase } from "../../../src/db/init.js";
import { runMigrations } from "../../../src/db/migrations.js";
import { createPool } from "../../../src/db/pool.js";

const rootPassword = "root-password-for-interactions-test";
const databaseName = "mailcow_mcp";
const databaseUser = "mailcow_mcp";
const databasePassword = "d".repeat(64);
export const encryptionKey = Buffer.from(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  "hex",
);
export const issuer = new URL("https://mail.example.test");
export const resource = new URL("https://mail.example.test/mcp");
export const redirectUri = "https://claude.ai/api/mcp/auth_callback";
export const verifierValue = "v".repeat(64);
const challenge = createHash("sha256")
  .update(verifierValue, "ascii")
  .digest("base64url");

export interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  json(): unknown;
}

export interface ConsentRow extends RowDataPacket {
  scopes: string;
  revoked: number;
}

export interface CountRow extends RowDataPacket {
  count: number;
}

export function storedConsentScopes(raw: string | undefined): string[] {
  const parsed: unknown = JSON.parse(raw ?? "[]");
  if (Array.isArray(parsed)) {
    return parsed as string[];
  }
  return (parsed as { scopes?: string[] }).scopes ?? [];
}

export class HttpClient {
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
        { host: "127.0.0.1", port: this.port, path, method, headers: requestHeaders },
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

  get(path: string, headers: Record<string, string> = {}): Promise<HttpResponse> {
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
  cookieSnapshot(): string {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

export function hidden(html: string, name: string): string {
  const expression = new RegExp(
    `<input[^>]+name="${name}"[^>]+value="([^"]+)"`,
    "u",
  );
  const value = expression.exec(html)?.[1];
  expect(value).toBeTypeOf("string");
  return value as string;
}

export function locationPath(response: HttpResponse): string {
  expect(response.status).toBe(303);
  expect(response.headers.location).toBeTypeOf("string");
  const target = new URL(response.headers.location as string, issuer);
  return `${target.pathname}${target.search}`;
}

export function authPath(clientId: string, scope: string): string {
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

export let pool: Pool;
export let provider: Provider;
export let client: HttpClient;
export let server: ReturnType<ReturnType<typeof createApp>["listen"]>;
export let app: ReturnType<typeof createApp>;
export let accountRepository: MariaDbAccountRepository;
export let authorityMutations: BoundedAuthorizationMutationCoordinator;
let container: StartedTestContainer;
let credentialVerifier: CredentialVerifier;

export const interactionState: {
  protocolAttempts: Array<{ mailbox: string; password: string }>;
  authenticationFailure: boolean;
  verificationDelayMs: number;
  verificationStarted: (() => void) | undefined;
} = {
  protocolAttempts: [],
  authenticationFailure: false,
  verificationDelayMs: 0,
  verificationStarted: undefined,
};

export function installInteractionsFixture(): void {
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
    interactionState.protocolAttempts = [];
    interactionState.authenticationFailure = false;
    interactionState.verificationDelayMs = 0;
    interactionState.verificationStarted = undefined;
    credentialVerifier = {
      async verify(mailbox, password) {
        interactionState.protocolAttempts.push({ mailbox, password });
        interactionState.verificationStarted?.();
        if (interactionState.verificationDelayMs > 0) {
          await new Promise((resolve) =>
            setTimeout(resolve, interactionState.verificationDelayMs),
          );
        }
        if (interactionState.authenticationFailure) {
          throw new Error(`protocol rejected ${mailbox} ${password}`);
        }
      },
    };
    accountRepository = new MariaDbAccountRepository(
      pool,
      new AesGcmCredentialVault(encryptionKey),
    );
    provider = await createOidcProvider({ pool, issuer, resource, encryptionKey });
    await startApp();
  });

  afterEach(async () => {
    await app.closeMcpSessions();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });
  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });
}

export async function startApp(
  overrides: {
    maximumInFlightInteractions?: number;
    maximumLoginQuotaEntries?: number;
    maximumConsentSessions?: number;
    maximumAuthorityMutations?: number;
    reauthenticationProofTtlMs?: number;
    proofNow?: () => number;
    verificationTimeoutMs?: number;
    mcpNow?: () => number;
  } = {},
): Promise<void> {
  if (server?.listening) {
    await app.closeMcpSessions();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
  const {
    maximumAuthorityMutations = 1_000,
    reauthenticationProofTtlMs = 10 * 60 * 1_000,
    proofNow,
    mcpNow,
    ...interactionOverrides
  } = overrides;
  authorityMutations = new BoundedAuthorizationMutationCoordinator(maximumAuthorityMutations);
  app = createApp({
    readiness: async () => true,
    resourceMetadataUrl: new URL("/.well-known/oauth-protected-resource/mcp", issuer),
    resource,
    oidcProvider: provider,
    ...(mcpNow === undefined ? {} : { mcpNow }),
    interactions: {
      accountRepository,
      credentialVerifier,
      pool,
      issuer,
      resource,
      encryptionKey,
      loginAttempts: 5,
      loginWindowSeconds: 900,
      authorityMutations,
      pendingReauthenticationTtlMs: reauthenticationProofTtlMs,
      ...(proofNow === undefined ? {} : { now: proofNow }),
      ...interactionOverrides,
    },
  });
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  client = new HttpClient((server.address() as AddressInfo).port);
}

export async function restartProviderAndApp(
  overrides: Parameters<typeof startApp>[0] = {},
): Promise<void> {
  provider = await createOidcProvider({ pool, issuer, resource, encryptionKey });
  await startApp(overrides);
}

export async function registerClient(): Promise<string> {
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
export async function loginPage(
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
export async function loginPageFor(
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
export async function submitLogin(
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
export async function reachConsent(
  loginResponse: HttpResponse,
): Promise<{ path: string; response: HttpResponse }> {
  const resume = await client.get(locationPath(loginResponse));
  const path = locationPath(resume);
  expect(path).toMatch(/^\/mcp-login\/[A-Za-z0-9_-]+$/u);
  const response = await client.get(path);
  expect(response.status).toBe(200);
  return { path, response };
}
export async function reachConsentFor(
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
export async function distinctLoginPages(
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
export async function accountIdForMailbox(mailbox = "user@example.test"): Promise<string> {
  const [rows] = await pool.query<
    Array<RowDataPacket & { accountId: string }>
  >(
    `SELECT LOWER(CONCAT(
       SUBSTR(HEX(id), 1, 8), '-',
       SUBSTR(HEX(id), 9, 4), '-',
       SUBSTR(HEX(id), 13, 4), '-',
       SUBSTR(HEX(id), 17, 4), '-',
       SUBSTR(HEX(id), 21)
     )) AS accountId
     FROM accounts
     WHERE mailbox_normalized = ?`,
    [mailbox],
  );
  expect(rows[0]?.accountId).toBeTypeOf("string");
  return rows[0]!.accountId;
}
export async function rawConsent(
  accountId: string,
  clientId: string,
): Promise<string> {
  const [rows] = await pool.query<
    Array<RowDataPacket & { value: string }>
  >(
    `SELECT CAST(scopes AS CHAR) AS value
     FROM consents
     WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
    [accountId, clientId],
  );
  expect(rows[0]?.value).toBeTypeOf("string");
  return rows[0]!.value;
}
