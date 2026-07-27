import {
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import type { Pool, RowDataPacket } from "mysql2/promise";
import type { Provider } from "oidc-provider";

import {
  normalizeMailbox,
  type AccountRepository,
} from "./account-repository.js";
import type { CredentialVerifier } from "./credential-verifier.js";
import { MCP_OAUTH_SCOPES } from "./oidc-provider.js";

const interactionPath = "/mcp-login/:interaction";
const csrfCookieName = "mailcow_mcp_interaction_csrf";
const csrfLifetimeSeconds = 600;
const maximumFormBytes = 16 * 1_024;
const maximumRateLimitEntries = 10_000;
const allowedScopeSet = new Set<string>(MCP_OAUTH_SCOPES);

interface InteractionDependencies {
  provider: Provider;
  accountRepository: AccountRepository;
  credentialVerifier: CredentialVerifier;
  pool: Pool;
  issuer: URL;
  resource: URL;
  encryptionKey: Uint8Array;
  loginAttempts: number;
  loginWindowSeconds: number;
  now?: () => number;
}

interface ConsentRow extends RowDataPacket {
  scopes: string;
}

interface Window {
  failures: number;
  startedAt: number;
}

class FailureQuota {
  private readonly windows = new Map<string, Window>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {}

  private sweep(currentTime: number): void {
    for (const [key, window] of this.windows) {
      if (currentTime - window.startedAt >= this.windowMs) {
        this.windows.delete(key);
      }
    }
  }

  isBlocked(key: string): boolean {
    const currentTime = this.now();
    this.sweep(currentTime);
    const existing = this.windows.get(key);
    if (existing !== undefined) {
      return existing.failures >= this.limit;
    }
    return this.windows.size >= maximumRateLimitEntries;
  }

  recordFailure(key: string): void {
    const currentTime = this.now();
    this.sweep(currentTime);
    const existing = this.windows.get(key);
    if (existing !== undefined) {
      existing.failures += 1;
      return;
    }
    if (this.windows.size < maximumRateLimitEntries) {
      this.windows.set(key, { failures: 1, startedAt: currentTime });
    }
  }

  retryAfter(key: string): number {
    const currentTime = this.now();
    const existing = this.windows.get(key);
    if (existing === undefined) {
      return Math.ceil(this.windowMs / 1_000);
    }
    return Math.max(
      1,
      Math.ceil(
        (existing.startedAt + this.windowMs - currentTime) / 1_000,
      ),
    );
  }
}

class LoginFailureLimiter {
  private readonly ip: FailureQuota;
  private readonly mailbox: FailureQuota;

  constructor(limit: number, windowMs: number, now: () => number) {
    this.ip = new FailureQuota(limit, windowMs, now);
    this.mailbox = new FailureQuota(limit, windowMs, now);
  }

  blocked(ip: string, mailbox?: string): boolean {
    return (
      this.ip.isBlocked(ip) ||
      (mailbox !== undefined && this.mailbox.isBlocked(mailbox))
    );
  }

  record(ip: string, mailbox?: string): void {
    this.ip.recordFailure(ip);
    if (mailbox !== undefined) {
      this.mailbox.recordFailure(mailbox);
    }
  }

  retryAfter(ip: string, mailbox?: string): number {
    return Math.max(
      this.ip.retryAfter(ip),
      mailbox === undefined ? 1 : this.mailbox.retryAfter(mailbox),
    );
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setSecretPageHeaders(response: Response): void {
  response.set({
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "Content-Security-Policy":
      "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Content-Type": "text/html; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title></head>
<body><main><h1>${escapeHtml(title)}</h1>${body}</main></body>
</html>`;
}

function renderLogin(
  response: Response,
  csrf: string,
  error = false,
): void {
  setSecretPageHeaders(response);
  response.status(error ? 401 : 200).send(
    page(
      "Connect your mailbox",
      `${error ? "<p>Authentication failed. Check the mailbox and app password.</p>" : ""}
<p>Use a dedicated mailcow app password restricted to IMAP and SMTP. These protocols cannot distinguish it from your primary password.</p>
<form method="post">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<label>Mailbox <input required autocomplete="username" type="email" name="mailbox"></label>
<label>App password <input required autocomplete="current-password" type="password" name="app_password"></label>
<button type="submit">Continue</button>
</form>`,
    ),
  );
}

function renderConsent(
  response: Response,
  csrf: string,
  scopes: readonly string[],
): void {
  const scopeItems = scopes
    .map((scope) => `<li>${escapeHtml(scope)}</li>`)
    .join("");
  setSecretPageHeaders(response);
  response.status(200).send(
    page(
      "Authorize mailbox access",
      `<p>Authorize this connector for:</p><ul>${scopeItems}</ul>
<form method="post">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit" name="decision" value="approve">Authorize</button>
<button type="submit" name="decision" value="revoke">Revoke access</button>
</form>`,
    ),
  );
}

function parseCookie(request: Request, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) {
      continue;
    }
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return undefined;
}

function equalMac(first: string, second: string): boolean {
  const firstBytes = Buffer.from(first, "base64url");
  const secondBytes = Buffer.from(second, "base64url");
  return (
    firstBytes.length === secondBytes.length &&
    timingSafeEqual(firstBytes, secondBytes)
  );
}

function csrfKey(encryptionKey: Uint8Array): Buffer {
  return createHmac("sha256", encryptionKey)
    .update("mailcow-mcp:interaction-csrf:v1", "utf8")
    .digest();
}

function csrfState(
  response: Response,
  interaction: string,
  key: Uint8Array,
  now: () => number,
): string {
  const expires = Math.floor(now() / 1_000) + csrfLifetimeSeconds;
  const nonce = randomBytes(24).toString("base64url");
  const cookieMac = createHmac("sha256", key)
    .update(`cookie:${expires}:${nonce}`, "utf8")
    .digest("base64url");
  const cookie = `v1.${expires}.${nonce}.${cookieMac}`;
  const tokenMac = createHmac("sha256", key)
    .update(`form:${expires}:${nonce}:${interaction}`, "utf8")
    .digest("base64url");

  response.setHeader(
    "Set-Cookie",
    `${csrfCookieName}=${cookie}; Path=/mcp-login; HttpOnly; Secure; SameSite=Lax`,
  );
  return `v1.${expires}.${tokenMac}`;
}

function validCsrf(
  request: Request,
  interaction: string,
  submitted: unknown,
  key: Uint8Array,
  now: () => number,
): boolean {
  if (typeof submitted !== "string") {
    return false;
  }
  const cookie = parseCookie(request, csrfCookieName);
  const cookieParts = cookie?.split(".");
  const tokenParts = submitted.split(".");
  if (
    cookieParts?.length !== 4 ||
    tokenParts.length !== 3 ||
    cookieParts[0] !== "v1" ||
    tokenParts[0] !== "v1" ||
    cookieParts[1] !== tokenParts[1] ||
    !/^[0-9]+$/u.test(cookieParts[1] ?? "") ||
    !/^[A-Za-z0-9_-]+$/u.test(cookieParts[2] ?? "") ||
    !/^[A-Za-z0-9_-]+$/u.test(cookieParts[3] ?? "") ||
    !/^[A-Za-z0-9_-]+$/u.test(tokenParts[2] ?? "")
  ) {
    return false;
  }
  const expires = Number(cookieParts[1]);
  if (
    !Number.isSafeInteger(expires) ||
    expires < Math.floor(now() / 1_000) ||
    expires > Math.floor(now() / 1_000) + csrfLifetimeSeconds
  ) {
    return false;
  }
  const expectedCookieMac = createHmac("sha256", key)
    .update(`cookie:${expires}:${cookieParts[2]}`, "utf8")
    .digest("base64url");
  const expectedTokenMac = createHmac("sha256", key)
    .update(`form:${expires}:${cookieParts[2]}:${interaction}`, "utf8")
    .digest("base64url");
  return (
    equalMac(cookieParts[3] as string, expectedCookieMac) &&
    equalMac(tokenParts[2] as string, expectedTokenMac)
  );
}

function requestIp(request: Request): string {
  return request.ip ?? request.socket.remoteAddress ?? "";
}

function safeReturnTo(
  returnTo: string,
  interaction: string,
  issuer: URL,
): boolean {
  try {
    const target = new URL(returnTo);
    return (
      target.origin === issuer.origin &&
      target.username === "" &&
      target.password === "" &&
      target.search === "" &&
      target.hash === "" &&
      target.pathname === `/oauth/auth/${encodeURIComponent(interaction)}`
    );
  } catch {
    return false;
  }
}

function bodyRecord(request: Request): Record<string, unknown> | undefined {
  const body: unknown = request.body;
  return typeof body === "object" && body !== null && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : undefined;
}

function requestedScopes(
  params: Record<string, unknown>,
  resource: URL,
): string[] | null {
  const requestedResource = params.resource;
  if (
    requestedResource !== resource.href &&
    !(
      Array.isArray(requestedResource) &&
      requestedResource.length === 1 &&
      requestedResource[0] === resource.href
    )
  ) {
    return null;
  }
  if (typeof params.scope !== "string") {
    return null;
  }
  const scopes = [...new Set(params.scope.split(" ").filter(Boolean))].sort();
  return (
    scopes.length > 0 && scopes.every((scope) => allowedScopeSet.has(scope))
      ? scopes
      : null
  );
}

function validAccountId(accountId: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
    accountId,
  );
}

async function loadConsent(
  pool: Pool,
  accountId: string,
  clientId: string,
): Promise<string[]> {
  if (!validAccountId(accountId)) {
    return [];
  }
  const [rows] = await pool.execute<ConsentRow[]>(
    `SELECT CAST(scopes AS CHAR) AS scopes
     FROM consents
     WHERE account_id = UNHEX(REPLACE(?, '-', ''))
       AND client_id = ? AND revoked_at IS NULL`,
    [accountId, clientId],
  );
  try {
    const value: unknown = JSON.parse(rows[0]?.scopes ?? "[]");
    return Array.isArray(value) &&
      value.every(
        (scope) => typeof scope === "string" && allowedScopeSet.has(scope),
      )
      ? [...new Set(value)].sort()
      : [];
  } catch {
    return [];
  }
}

async function saveConsent(
  pool: Pool,
  accountId: string,
  clientId: string,
  scopes: readonly string[],
): Promise<void> {
  if (!validAccountId(accountId)) {
    throw new Error("invalid account");
  }
  await pool.execute(
    `INSERT INTO consents (
       account_id, client_id, scopes, created_at, revoked_at
     ) VALUES (
       UNHEX(REPLACE(?, '-', '')), ?, ?, UTC_TIMESTAMP(6), NULL
     )
     ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), revoked_at = NULL`,
    [accountId, clientId, JSON.stringify([...scopes].sort())],
  );
}

async function revokeConsent(
  dependencies: InteractionDependencies,
  accountId: string,
  clientId: string,
  grantId?: string,
): Promise<void> {
  if (validAccountId(accountId)) {
    await dependencies.pool.execute(
      `UPDATE consents SET revoked_at = UTC_TIMESTAMP(6)
       WHERE account_id = UNHEX(REPLACE(?, '-', '')) AND client_id = ?`,
      [accountId, clientId],
    );
  }
  if (grantId === undefined) {
    return;
  }
  await Promise.all([
    dependencies.provider.AccessToken.revokeByGrantId(grantId),
    dependencies.provider.AuthorizationCode.revokeByGrantId(grantId),
    dependencies.provider.RefreshToken.revokeByGrantId(grantId),
  ]);
  const grant = await dependencies.provider.Grant.find(grantId);
  await grant?.destroy();
}

async function finishConsent(
  request: Request,
  response: Response,
  dependencies: InteractionDependencies,
  accountId: string,
  clientId: string,
  grantScopes: readonly string[],
  grantId?: string,
  consentScopes: readonly string[] = grantScopes,
): Promise<void> {
  let grant =
    grantId === undefined
      ? undefined
      : await dependencies.provider.Grant.find(grantId);
  grant ??= new dependencies.provider.Grant({ accountId, clientId });
  grant.addResourceScope(
    dependencies.resource.href,
    grantScopes.join(" "),
  );
  const savedGrantId = await grant.save();
  await saveConsent(
    dependencies.pool,
    accountId,
    clientId,
    consentScopes,
  );
  await dependencies.provider.interactionFinished(
    request,
    response,
    { consent: { grantId: savedGrantId } },
    { mergeWithLastSubmission: false },
  );
}

function reject(
  response: Response,
  status: number,
  message: string,
  retryAfter?: number,
): void {
  setSecretPageHeaders(response);
  if (retryAfter !== undefined) {
    response.set("Retry-After", retryAfter.toString());
  }
  response.status(status).send(message);
}

export function createInteractionRouter(
  dependencies: InteractionDependencies,
): Router {
  if (
    !Number.isSafeInteger(dependencies.loginAttempts) ||
    dependencies.loginAttempts < 1 ||
    !Number.isSafeInteger(dependencies.loginWindowSeconds) ||
    dependencies.loginWindowSeconds < 1
  ) {
    throw new Error("invalid login rate limit");
  }
  const router = express.Router();
  const now = dependencies.now ?? Date.now;
  const key = csrfKey(dependencies.encryptionKey);
  const limiter = new LoginFailureLimiter(
    dependencies.loginAttempts,
    dependencies.loginWindowSeconds * 1_000,
    now,
  );
  const inFlight = new Set<string>();

  const precheckIp: RequestHandler = (request, response, next) => {
    const ip = requestIp(request);
    if (limiter.blocked(ip)) {
      reject(
        response,
        429,
        "Too many authentication attempts.",
        limiter.retryAfter(ip),
      );
      return;
    }
    next();
  };
  const parseForm = express.urlencoded({
    extended: false,
    limit: maximumFormBytes,
  });
  const formError = (
    error: unknown,
    request: Request,
    response: Response,
    next: NextFunction,
  ): void => {
    if (error === undefined) {
      next();
      return;
    }
    limiter.record(requestIp(request));
    const status =
      typeof error === "object" &&
      error !== null &&
      "status" in error &&
      error.status === 413
        ? 413
        : 400;
    reject(response, status, "Invalid authentication request.");
  };

  router.get(interactionPath, async (request, response) => {
    try {
      const details = await dependencies.provider.interactionDetails(
        request,
        response,
      );
      if (
        details.uid !== request.params.interaction ||
        !safeReturnTo(details.returnTo, details.uid, dependencies.issuer)
      ) {
        reject(response, 400, "Invalid interaction.");
        return;
      }
      const csrf = csrfState(
        response,
        details.uid,
        key,
        now,
      );
      if (details.prompt.name === "login") {
        renderLogin(response, csrf);
        return;
      }
      if (details.prompt.name !== "consent") {
        reject(response, 400, "Unsupported interaction.");
        return;
      }
      const params = details.params as Record<string, unknown>;
      const accountId = details.session?.accountId;
      const clientId = params.client_id;
      const scopes = requestedScopes(params, dependencies.resource);
      if (
        accountId === undefined ||
        typeof clientId !== "string" ||
        scopes === null
      ) {
        reject(response, 400, "Invalid interaction.");
        return;
      }
      const existingScopes = await loadConsent(
        dependencies.pool,
        accountId,
        clientId,
      );
      if (
        scopes.every((scope) => existingScopes.includes(scope))
      ) {
        await finishConsent(
          request,
          response,
          dependencies,
          accountId,
          clientId,
          scopes,
          details.grantId,
          existingScopes,
        );
        return;
      }
      renderConsent(response, csrf, scopes);
    } catch {
      if (!response.headersSent) {
        reject(response, 400, "Invalid interaction.");
      }
    }
  });

  router.post(
    interactionPath,
    precheckIp,
    parseForm,
    async (request: Request, response: Response) => {
      let interaction = request.params.interaction;
      if (typeof interaction !== "string") {
        reject(response, 400, "Invalid interaction.");
        return;
      }
      const body = bodyRecord(request);
      if (body === undefined) {
        limiter.record(requestIp(request));
        reject(response, 403, "Invalid request.");
        return;
      }
      if (!validCsrf(
        request,
        interaction,
        body.csrf,
        key,
        now,
      )) {
        reject(response, 403, "Invalid request.");
        return;
      }
      if (inFlight.has(interaction)) {
        reject(response, 409, "Interaction is already being processed.");
        return;
      }
      inFlight.add(interaction);
      try {
        const details = await dependencies.provider.interactionDetails(
          request,
          response,
        );
        if (
          details.uid !== interaction ||
          !safeReturnTo(details.returnTo, details.uid, dependencies.issuer)
        ) {
          reject(response, 400, "Invalid interaction.");
          return;
        }
        if (details.prompt.name === "login") {
          const mailboxInput = body.mailbox;
          const appPassword = body.app_password;
          if (
            typeof mailboxInput !== "string" ||
            typeof appPassword !== "string" ||
            appPassword === ""
          ) {
            limiter.record(requestIp(request));
            renderLogin(response, body.csrf as string, true);
            return;
          }
          let mailbox: string;
          try {
            mailbox = normalizeMailbox(mailboxInput);
          } catch {
            limiter.record(requestIp(request));
            renderLogin(response, body.csrf as string, true);
            return;
          }
          const ip = requestIp(request);
          const mailboxKey = mailbox.toLowerCase();
          if (limiter.blocked(ip, mailboxKey)) {
            reject(
              response,
              429,
              "Too many authentication attempts.",
              limiter.retryAfter(ip, mailboxKey),
            );
            return;
          }
          try {
            await dependencies.credentialVerifier.verify(
              mailbox,
              appPassword,
            );
            const accountId =
              await dependencies.accountRepository.upsertVerified(
                mailbox,
                appPassword,
              );
            await dependencies.provider.interactionFinished(
              request,
              response,
              { login: { accountId } },
              { mergeWithLastSubmission: false },
            );
          } catch {
            limiter.record(ip, mailboxKey);
            renderLogin(response, body.csrf as string, true);
          }
          return;
        }
        if (details.prompt.name !== "consent") {
          reject(response, 400, "Unsupported interaction.");
          return;
        }
        const params = details.params as Record<string, unknown>;
        const accountId = details.session?.accountId;
        const clientId = params.client_id;
        const scopes = requestedScopes(params, dependencies.resource);
        if (
          accountId === undefined ||
          typeof clientId !== "string" ||
          scopes === null
        ) {
          reject(response, 400, "Invalid interaction.");
          return;
        }
        if (body.decision === "revoke") {
          await revokeConsent(
            dependencies,
            accountId,
            clientId,
            details.grantId,
          );
          await dependencies.provider.interactionFinished(
            request,
            response,
            {
              error: "access_denied",
              error_description: "Mailbox access was revoked",
            },
            { mergeWithLastSubmission: false },
          );
          return;
        }
        if (body.decision !== "approve") {
          reject(response, 400, "Invalid interaction.");
          return;
        }
        const existingScopes = await loadConsent(
          dependencies.pool,
          accountId,
          clientId,
        );
        const persistedScopes = [
          ...new Set([...existingScopes, ...scopes]),
        ].sort();
        await finishConsent(
          request,
          response,
          dependencies,
          accountId,
          clientId,
          scopes,
          details.grantId,
          persistedScopes,
        );
      } catch {
        if (!response.headersSent) {
          reject(response, 400, "Invalid interaction.");
        }
      } finally {
        inFlight.delete(interaction);
      }
    },
    formError,
  );

  return router;
}

export type { InteractionDependencies };
