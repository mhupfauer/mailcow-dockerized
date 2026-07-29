import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import type { Pool } from "mysql2/promise";
import type { InteractionResults, Provider } from "oidc-provider";

import {
  normalizeMailbox,
  type AccountRepository,
} from "./account-repository.js";
import {
  CleanupPendingAuthorizationError,
  InactiveAuthorizationAccountError,
  InvalidReauthenticationProofError,
  MariaDbConsentAuthorizationRepository,
  type AuthorizationMutationCoordinator,
} from "./authorization-state.js";
import {
  revokeProviderAuthority,
  revokeProviderAuthorityBestEffort,
} from "./authorization-revoker.js";
import type {
  ConsentAuthorizationState,
  ReauthenticationBridge,
} from "./consent-authorization-codec.js";
import type { CredentialVerifier } from "./credential-verifier.js";
import { AesGcmCredentialVault } from "./crypto-vault.js";
import { MCP_OAUTH_SCOPES } from "./oidc-provider.js";

const interactionPath = "/mcp-login/:interaction";
const csrfCookieName = "mailcow_mcp_interaction_csrf";
const csrfLifetimeSeconds = 600;
const maximumFormBytes = 16 * 1_024;
const defaultMaximumConsentSessions = 32;
const defaultMaximumRetiredReauthenticationBridges = 128;
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
  maximumInFlightInteractions?: number;
  maximumLoginQuotaEntries?: number;
  maximumConsentSessions?: number;
  maximumRetiredReauthenticationBridges?: number;
  verificationTimeoutMs?: number;
  pendingReauthenticationTtlMs?: number;
  authorityMutations: AuthorizationMutationCoordinator;
  now?: () => number;
}

interface Window {
  failures: number;
  inFlight: number;
  startedAt: number;
}

interface FailureReservation {
  release(): void;
  retainFailure(): void;
}

class FailureQuota {
  private readonly windows = new Map<string, Window>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxEntries: number,
    private readonly now: () => number,
  ) {}

  private sweep(currentTime: number): void {
    for (const [key, window] of this.windows) {
      if (
        window.inFlight === 0 &&
        currentTime - window.startedAt >= this.windowMs
      ) {
        this.windows.delete(key);
      }
    }
  }

  isBlocked(key: string): boolean {
    const currentTime = this.now();
    this.sweep(currentTime);
    const existing = this.windows.get(key);
    if (existing !== undefined) {
      return existing.failures + existing.inFlight >= this.limit;
    }
    return this.windows.size >= this.maxEntries;
  }

  reserve(key: string): FailureReservation | null {
    const currentTime = this.now();
    this.sweep(currentTime);
    let window = this.windows.get(key);
    if (window === undefined) {
      if (this.windows.size >= this.maxEntries) {
        return null;
      }
      window = { failures: 0, inFlight: 0, startedAt: currentTime };
      this.windows.set(key, window);
    }
    if (window.failures + window.inFlight >= this.limit) {
      return null;
    }
    window.inFlight += 1;
    let settled = false;
    const settle = (failure: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      window.inFlight -= 1;
      if (failure) {
        if (window.failures === 0) {
          window.startedAt = this.now();
        }
        window.failures = Math.min(this.limit, window.failures + 1);
      } else if (window.failures === 0 && window.inFlight === 0) {
        this.windows.delete(key);
      }
    };
    return {
      release: () => settle(false),
      retainFailure: () => settle(true),
    };
  }

  recordFailure(key: string): void {
    const currentTime = this.now();
    this.sweep(currentTime);
    const existing = this.windows.get(key);
    if (existing !== undefined) {
      existing.failures += 1;
      return;
    }
    if (this.windows.size < this.maxEntries) {
      this.windows.set(key, {
        failures: 1,
        inFlight: 0,
        startedAt: currentTime,
      });
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
      Math.ceil((existing.startedAt + this.windowMs - currentTime) / 1_000),
    );
  }
}

class LoginFailureLimiter {
  private readonly ip: FailureQuota;
  private readonly mailbox: FailureQuota;

  constructor(
    limit: number,
    windowMs: number,
    maxEntries: number,
    now: () => number,
  ) {
    this.ip = new FailureQuota(limit, windowMs, maxEntries, now);
    this.mailbox = new FailureQuota(limit, windowMs, maxEntries, now);
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

  reserve(ip: string, mailbox: string): FailureReservation | null {
    const ipReservation = this.ip.reserve(ip);
    if (ipReservation === null) {
      return null;
    }
    const mailboxReservation = this.mailbox.reserve(mailbox);
    if (mailboxReservation === null) {
      ipReservation.release();
      return null;
    }
    let settled = false;
    return {
      release() {
        if (settled) {
          return;
        }
        settled = true;
        ipReservation.release();
        mailboxReservation.release();
      },
      retainFailure() {
        if (settled) {
          return;
        }
        settled = true;
        ipReservation.retainFailure();
        mailboxReservation.retainFailure();
      },
    };
  }

  retryAfter(ip: string, mailbox?: string): number {
    return Math.max(
      this.ip.retryAfter(ip),
      mailbox === undefined ? 1 : this.mailbox.retryAfter(mailbox),
    );
  }
}

type LockResult =
  | { status: "acquired"; release(): void }
  | { status: "duplicate" }
  | { status: "full" };

class BoundedInteractionLock {
  private readonly keys = new Set<string>();

  constructor(private readonly maximum: number) {}

  acquire(key: string): LockResult {
    if (this.keys.has(key)) {
      return { status: "duplicate" };
    }
    if (this.keys.size >= this.maximum) {
      return { status: "full" };
    }
    this.keys.add(key);
    let released = false;
    return {
      status: "acquired",
      release: () => {
        if (!released) {
          released = true;
          this.keys.delete(key);
        }
      },
    };
  }
}

async function verifyCredential(
  dependencies: InteractionDependencies,
  mailbox: string,
  appPassword: string,
): Promise<void> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, rejectTimeout) => {
    timeout = setTimeout(() => {
      controller.abort();
      rejectTimeout(new Error("credential verification timed out"));
    }, dependencies.verificationTimeoutMs ?? 15_000);
  });
  try {
    await Promise.race([
      dependencies.credentialVerifier.verify(
        mailbox,
        appPassword,
        controller.signal,
      ),
      timeoutPromise,
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
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

function renderLogin(response: Response, csrf: string, error = false): void {
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
  return scopes.length > 0 &&
    scopes.every((scope) => allowedScopeSet.has(scope))
    ? scopes
    : null;
}

function reauthenticationBridge(
  lastSubmission: unknown,
): ReauthenticationBridge | undefined {
  if (
    typeof lastSubmission !== "object" ||
    lastSubmission === null ||
    Array.isArray(lastSubmission)
  ) {
    return undefined;
  }
  const login = (lastSubmission as Record<string, unknown>).login;
  if (typeof login !== "object" || login === null || Array.isArray(login)) {
    return undefined;
  }
  const record = login as Record<string, unknown>;
  const proof = record.reauthenticationProof;
  const authorizationEpoch = record.authorizationEpoch;
  const expiresAt = record.reauthenticationExpiresAt;
  const bindingEnvelope = record.reauthenticationBinding;
  return typeof proof === "string" &&
    proof !== "" &&
    typeof authorizationEpoch === "string" &&
    authorizationEpoch !== "" &&
    Number.isSafeInteger(expiresAt) &&
    typeof bindingEnvelope === "string" &&
    bindingEnvelope !== ""
    ? {
        proof,
        authorizationEpoch,
        expiresAt: expiresAt as number,
        bindingEnvelope,
      }
    : undefined;
}

async function finishConsent(
  request: Request,
  response: Response,
  dependencies: InteractionDependencies,
  accountId: string,
  clientId: string,
  grantScopes: readonly string[],
  existingState: ConsentAuthorizationState | null,
  currentGrantId: string | undefined,
  currentSessionId: string,
  consentRepository: MariaDbConsentAuthorizationRepository,
  maximumConsentSessions: number,
  bridge: ReauthenticationBridge | undefined,
  now: number,
  consentScopes: readonly string[] = grantScopes,
): Promise<void> {
  const canonicalGrantId =
    existingState?.lifecycle === "active" ||
    existingState?.lifecycle === "pending_reauth"
      ? existingState.grantId
      : undefined;
  let grant =
    canonicalGrantId === undefined
      ? undefined
      : await dependencies.provider.Grant.find(canonicalGrantId);
  if (grant === undefined && currentGrantId !== undefined) {
    grant = await dependencies.provider.Grant.find(currentGrantId);
  }
  grant ??= new dependencies.provider.Grant({ accountId, clientId });
  grant.addResourceScope(dependencies.resource.href, grantScopes.join(" "));
  const savedGrantId = await grant.save();
  const sessionIds =
    existingState?.lifecycle === "active" ||
    existingState?.lifecycle === "pending_reauth"
      ? [...existingState.sessionIds]
      : [];
  if (!sessionIds.includes(currentSessionId)) {
    if (sessionIds.length >= maximumConsentSessions) {
      const evictedSessionId = sessionIds.shift();
      if (evictedSessionId !== undefined) {
        await revokeProviderAuthority(
          dependencies.provider,
          [],
          [evictedSessionId],
        );
      }
    }
    sessionIds.push(currentSessionId);
  }
  try {
    if (existingState?.lifecycle === "pending_reauth") {
      if (bridge === undefined) {
        throw new InvalidReauthenticationProofError();
      }
      await consentRepository.activatePending(
        accountId,
        clientId,
        dependencies.resource.href,
        currentSessionId,
        bridge,
        now,
        {
          scopes: consentScopes,
          grantId: savedGrantId,
          sessionIds,
        },
      );
    } else {
      await consentRepository.updateActive(
        accountId,
        clientId,
        dependencies.resource.href,
        {
          scopes: consentScopes,
          grantId: savedGrantId,
          sessionIds,
        },
      );
    }
  } catch (error) {
    await revokeProviderAuthorityBestEffort(
      dependencies.provider,
      [
        savedGrantId,
        ...(canonicalGrantId === undefined ? [] : [canonicalGrantId]),
        ...(currentGrantId === undefined ? [] : [currentGrantId]),
      ],
      [...sessionIds, currentSessionId],
    );
    throw error;
  }
  const obsoleteGrantIds = [canonicalGrantId, currentGrantId].filter(
    (grantId): grantId is string =>
      grantId !== undefined && grantId !== savedGrantId,
  );
  await revokeProviderAuthority(dependencies.provider, obsoleteGrantIds, []);
  await dependencies.provider.interactionFinished(
    request,
    response,
    { consent: { grantId: savedGrantId } },
    { mergeWithLastSubmission: false },
  );
}

async function quarantineUnsafeAuthority(
  dependencies: InteractionDependencies,
  consentRepository: MariaDbConsentAuthorizationRepository,
  accountId: string,
  clientId: string,
  currentGrantId: string | undefined,
  currentSessionId: string,
): Promise<void> {
  const state = await consentRepository.quarantine(accountId, clientId);
  await revokeProviderAuthorityBestEffort(
    dependencies.provider,
    [
      ...(state?.grantId === undefined ? [] : [state.grantId]),
      ...(currentGrantId === undefined ? [] : [currentGrantId]),
    ],
    [...(state?.sessionIds ?? []), currentSessionId],
  );
}

async function finalizeStrandedCleanup(
  dependencies: InteractionDependencies,
  consentRepository: MariaDbConsentAuthorizationRepository,
  accountId: string,
  clientId: string,
  currentGrantId: string | undefined,
  currentSessionId: string,
  bridge: ReauthenticationBridge | undefined,
  now: number,
): Promise<void> {
  const retained = await consentRepository.retainCleanupFinalizer(
    accountId,
    clientId,
    dependencies.resource.href,
    currentSessionId,
    bridge,
    now,
  );
  await revokeProviderAuthorityBestEffort(
    dependencies.provider,
    [
      ...(retained.grantId === undefined ? [] : [retained.grantId]),
      ...(currentGrantId === undefined ? [] : [currentGrantId]),
    ],
    retained.sessionIds,
  );
  await consentRepository.completeClientCleanup(accountId, clientId);
}

async function finishRevocation(
  request: Request,
  response: Response,
  dependencies: InteractionDependencies,
  consentRepository: MariaDbConsentAuthorizationRepository,
  accountId: string,
  clientId: string,
  currentGrantId: string | undefined,
  currentSessionId: string,
): Promise<void> {
  const cleanup = await consentRepository.beginClientCleanup(
    accountId,
    clientId,
    currentSessionId,
  );
  if (cleanup?.lifecycle === "quarantined") {
    await revokeProviderAuthorityBestEffort(
      dependencies.provider,
      [
        ...(cleanup.grantId === undefined ? [] : [cleanup.grantId]),
        ...(currentGrantId === undefined ? [] : [currentGrantId]),
      ],
      [...cleanup.sessionIds, currentSessionId],
    );
    throw new InactiveAuthorizationAccountError();
  }
  await revokeProviderAuthority(
    dependencies.provider,
    [
      ...(cleanup?.grantId === undefined ? [] : [cleanup.grantId]),
      ...(currentGrantId === undefined ? [] : [currentGrantId]),
    ],
    (cleanup?.sessionIds ?? []).filter(
      (sessionId) => sessionId !== currentSessionId,
    ),
  );
  let finalizing = cleanup;
  let returnTo = cleanup?.cleanupReturnTo;
  if (returnTo === undefined) {
    returnTo = await dependencies.provider.interactionResult(
      request,
      response,
      {
        error: "access_denied",
        error_description: "Mailbox access was revoked",
      },
      { mergeWithLastSubmission: false },
    );
    const interaction = request.params.interaction;
    if (
      typeof interaction !== "string" ||
      !safeReturnTo(returnTo, interaction, dependencies.issuer)
    ) {
      throw new Error("invalid provider interaction result");
    }
    if (cleanup?.lifecycle === "cleanup_pending") {
      finalizing =
        await consentRepository.stageClientCleanupFinalization(
          accountId,
          clientId,
          returnTo,
        );
    }
  } else {
    const interaction = request.params.interaction;
    if (
      typeof interaction !== "string" ||
      !safeReturnTo(returnTo, interaction, dependencies.issuer)
    ) {
      throw new Error("invalid retained provider interaction result");
    }
  }
  await revokeProviderAuthority(dependencies.provider, [], [currentSessionId]);
  if (
    finalizing?.lifecycle === "cleanup_pending" ||
    finalizing?.lifecycle === "cleanup_finalizing"
  ) {
    await consentRepository.completeClientCleanup(accountId, clientId);
  }
  response.statusCode = 303;
  response.setHeader("Location", returnTo);
  response.setHeader("Content-Length", "0");
  response.end();
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
  const maximumInFlightInteractions =
    dependencies.maximumInFlightInteractions ?? 1_000;
  const maximumLoginQuotaEntries =
    dependencies.maximumLoginQuotaEntries ?? 10_000;
  const verificationTimeoutMs = dependencies.verificationTimeoutMs ?? 15_000;
  const maximumConsentSessions =
    dependencies.maximumConsentSessions ?? defaultMaximumConsentSessions;
  const maximumRetiredReauthenticationBridges =
    dependencies.maximumRetiredReauthenticationBridges ??
    defaultMaximumRetiredReauthenticationBridges;
  const pendingReauthenticationTtlMs =
    dependencies.pendingReauthenticationTtlMs ?? 10 * 60 * 1_000;
  if (
    !Number.isSafeInteger(dependencies.loginAttempts) ||
    dependencies.loginAttempts < 1 ||
    !Number.isSafeInteger(dependencies.loginWindowSeconds) ||
    dependencies.loginWindowSeconds < 1 ||
    !Number.isSafeInteger(maximumInFlightInteractions) ||
    maximumInFlightInteractions < 1 ||
    !Number.isSafeInteger(maximumLoginQuotaEntries) ||
    maximumLoginQuotaEntries < 1 ||
    !Number.isSafeInteger(verificationTimeoutMs) ||
    verificationTimeoutMs < 1 ||
    !Number.isSafeInteger(maximumConsentSessions) ||
    maximumConsentSessions < 1 ||
    !Number.isSafeInteger(maximumRetiredReauthenticationBridges) ||
    maximumRetiredReauthenticationBridges < 1 ||
    maximumRetiredReauthenticationBridges > 1_024 ||
    !Number.isSafeInteger(pendingReauthenticationTtlMs) ||
    pendingReauthenticationTtlMs < 1
  ) {
    throw new Error("invalid login rate limit");
  }
  const router = express.Router();
  const now = dependencies.now ?? Date.now;
  const key = csrfKey(dependencies.encryptionKey);
  const limiter = new LoginFailureLimiter(
    dependencies.loginAttempts,
    dependencies.loginWindowSeconds * 1_000,
    maximumLoginQuotaEntries,
    now,
  );
  const interactionLock = new BoundedInteractionLock(
    maximumInFlightInteractions,
  );
  const consentRepository = new MariaDbConsentAuthorizationRepository(
    dependencies.pool,
    new AesGcmCredentialVault(dependencies.encryptionKey),
    dependencies.resource.href,
    {
      maximumSessions: maximumConsentSessions,
      maximumRetiredReauthenticationBridges,
    },
  );

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
      const csrf = csrfState(response, details.uid, key, now);
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
      const sessionId = details.session?.uid;
      const clientId = params.client_id;
      const scopes = requestedScopes(params, dependencies.resource);
      if (
        accountId === undefined ||
        typeof sessionId !== "string" ||
        sessionId === "" ||
        typeof clientId !== "string" ||
        scopes === null
      ) {
        reject(response, 400, "Invalid interaction.");
        return;
      }
      const authorityLease = await dependencies.authorityMutations.acquire(
        accountId,
        clientId,
        dependencies.resource.href,
      );
      if (authorityLease === null) {
        reject(response, 503, "Authorization service is busy.");
        return;
      }
      try {
        const bridge = reauthenticationBridge(details.lastSubmission);
        const storedState =
          bridge === undefined
            ? await consentRepository.getStored(accountId, clientId)
            : await consentRepository.stagePendingReauthentication(
                accountId,
                clientId,
                dependencies.resource.href,
                sessionId,
                bridge,
                now(),
              );
        if (
          storedState?.needsQuarantine === true ||
          storedState?.lifecycle === "quarantined"
        ) {
          await quarantineUnsafeAuthority(
            dependencies,
            consentRepository,
            accountId,
            clientId,
            details.grantId,
            sessionId,
          );
          reject(response, 401, "Reconnect mailbox access.");
          return;
        }
        if (storedState?.lifecycle === "cleanup_finalizing") {
          await finalizeStrandedCleanup(
            dependencies,
            consentRepository,
            accountId,
            clientId,
            details.grantId,
            sessionId,
            bridge,
            now(),
          );
          reject(response, 401, "Reconnect mailbox access.");
          return;
        }
        if (storedState?.lifecycle === "cleanup_pending") {
          renderConsent(response, csrf, scopes);
          return;
        }
        if (
          storedState === null ||
          storedState.lifecycle === "revoked" ||
          (
            storedState.lifecycle === "pending_reauth" &&
            bridge === undefined
          )
        ) {
          await revokeProviderAuthorityBestEffort(
            dependencies.provider,
            details.grantId === undefined ? [] : [details.grantId],
            [sessionId],
          );
          reject(response, 401, "Reconnect mailbox access.");
          return;
        }
        const existingState =
          storedState.lifecycle === "active" ||
          storedState.lifecycle === "pending_reauth"
            ? storedState
            : null;
        if (
          existingState !== null &&
          existingState.grantId !== undefined &&
          scopes.every((scope) => existingState.scopes.includes(scope))
        ) {
          await finishConsent(
            request,
            response,
            dependencies,
            accountId,
            clientId,
            scopes,
            existingState,
            details.grantId,
            sessionId,
            consentRepository,
            maximumConsentSessions,
            bridge,
            now(),
            existingState.scopes,
          );
          return;
        }
        renderConsent(response, csrf, scopes);
      } catch (error) {
        if (!response.headersSent) {
          const denied =
            error instanceof InactiveAuthorizationAccountError ||
            error instanceof InvalidReauthenticationProofError;
          reject(
            response,
            denied ? 401 : 503,
            denied
              ? "Reconnect mailbox access."
              : "Authorization service is unavailable.",
          );
        }
      } finally {
        authorityLease.release();
      }
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
      if (!validCsrf(request, interaction, body.csrf, key, now)) {
        reject(response, 403, "Invalid request.");
        return;
      }
      const lock = interactionLock.acquire(interaction);
      if (lock.status === "duplicate") {
        reject(response, 409, "Interaction is already being processed.");
        return;
      }
      if (lock.status === "full") {
        reject(response, 503, "Authentication service is busy.");
        return;
      }
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
          const clientId = (details.params as Record<string, unknown>)
            .client_id;
          const mailboxInput = body.mailbox;
          const appPassword = body.app_password;
          if (
            typeof clientId !== "string" ||
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
          const reservation = limiter.reserve(ip, mailboxKey);
          if (reservation === null) {
            reject(
              response,
              429,
              "Too many authentication attempts.",
              limiter.retryAfter(ip, mailboxKey),
            );
            return;
          }
          try {
            await verifyCredential(dependencies, mailbox, appPassword);
          } catch {
            reservation.retainFailure();
            renderLogin(response, body.csrf as string, true);
            return;
          }
          reservation.release();
          try {
            const verified =
              await dependencies.accountRepository
                .upsertVerifiedForAuthorization(
                  mailbox,
                  appPassword,
                );
            const proof = randomBytes(32).toString("base64url");
            const expiresAt = now() + pendingReauthenticationTtlMs;
            const bridge =
              await consentRepository.issueReauthenticationBridge(
                verified.accountId,
                clientId,
                dependencies.resource.href,
                {
                  proof,
                  authorizationEpoch: verified.authorizationEpoch,
                  expiresAt,
                },
              );
            await dependencies.provider.interactionFinished(
              request,
              response,
              {
                login: {
                  accountId: verified.accountId,
                  reauthenticationProof: bridge.proof,
                  authorizationEpoch: bridge.authorizationEpoch,
                  reauthenticationExpiresAt: bridge.expiresAt,
                  reauthenticationBinding: bridge.bindingEnvelope,
                },
              } as InteractionResults,
              { mergeWithLastSubmission: false },
            );
          } catch {
            if (!response.headersSent) {
              reject(
                response,
                503,
                "Authentication service is unavailable.",
              );
            }
          }
          return;
        }
        if (details.prompt.name !== "consent") {
          reject(response, 400, "Unsupported interaction.");
          return;
        }
        const params = details.params as Record<string, unknown>;
        const accountId = details.session?.accountId;
        const sessionId = details.session?.uid;
        const clientId = params.client_id;
        const scopes = requestedScopes(params, dependencies.resource);
        if (
          accountId === undefined ||
          typeof sessionId !== "string" ||
          sessionId === "" ||
          typeof clientId !== "string" ||
          scopes === null
        ) {
          reject(response, 400, "Invalid interaction.");
          return;
        }
        const authorityLease = await dependencies.authorityMutations.acquire(
          accountId,
          clientId,
          dependencies.resource.href,
        );
        if (authorityLease === null) {
          reject(response, 503, "Authorization service is busy.");
          return;
        }
        try {
          const bridge = reauthenticationBridge(details.lastSubmission);
          const storedState =
            bridge === undefined
              ? await consentRepository.getStored(accountId, clientId)
              : await consentRepository.stagePendingReauthentication(
                  accountId,
                  clientId,
                  dependencies.resource.href,
                  sessionId,
                  bridge,
                  now(),
                );
          if (
            storedState?.needsQuarantine === true ||
            storedState?.lifecycle === "quarantined"
          ) {
            await quarantineUnsafeAuthority(
              dependencies,
              consentRepository,
              accountId,
              clientId,
              details.grantId,
              sessionId,
            );
            reject(response, 401, "Reconnect mailbox access.");
            return;
          }
          if (body.decision === "revoke") {
            await finishRevocation(
              request,
              response,
              dependencies,
              consentRepository,
              accountId,
              clientId,
              details.grantId,
              sessionId,
            );
            return;
          }
          if (storedState?.lifecycle === "cleanup_finalizing") {
            await finalizeStrandedCleanup(
              dependencies,
              consentRepository,
              accountId,
              clientId,
              details.grantId,
              sessionId,
              bridge,
              now(),
            );
            reject(response, 401, "Reconnect mailbox access.");
            return;
          }
          if (body.decision !== "approve") {
            reject(response, 400, "Invalid interaction.");
            return;
          }
          if (storedState?.lifecycle === "cleanup_pending") {
            throw new CleanupPendingAuthorizationError();
          }
          if (
            storedState === null ||
            storedState.lifecycle === "revoked" ||
            (
              storedState.lifecycle === "pending_reauth" &&
              bridge === undefined
            )
          ) {
            throw new InactiveAuthorizationAccountError();
          }
          const existingState =
            storedState.lifecycle === "active" ||
            storedState.lifecycle === "pending_reauth"
              ? storedState
              : null;
          const existingScopes = existingState?.scopes ?? [];
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
            existingState,
            details.grantId,
            sessionId,
            consentRepository,
            maximumConsentSessions,
            bridge,
            now(),
            persistedScopes,
          );
        } catch (error) {
          if (!response.headersSent) {
            const denied =
              error instanceof InactiveAuthorizationAccountError ||
              error instanceof InvalidReauthenticationProofError;
            reject(
              response,
              denied ? 401 : 503,
              denied
                ? "Reconnect mailbox access."
                : "Authorization service is unavailable.",
            );
          }
        } finally {
          authorityLease.release();
        }
      } catch {
        if (!response.headersSent) {
          reject(response, 400, "Invalid interaction.");
        }
      } finally {
        lock.release();
      }
    },
    formError,
  );

  return router;
}

export type { InteractionDependencies };
