import { randomUUID } from "node:crypto";

import type { RequestHandler } from "express";

import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { requireAccountContext } from "./context.js";
import { createMcpServer } from "./server.js";
import { createIpRateLimiter } from "../http/rate-limit.js";

const sessionInactivityMs = 30 * 60 * 1_000;
const defaultMaximumTotalSessions = 256;
const defaultMaximumSessionsPerAuthority = 8;
const defaultMaximumInitializationsInFlight = 16;
const defaultInitializationsPerWindow = 10;
const defaultInitializationWindowMs = 60_000;
const capacityRetryAfterSeconds = 1;

interface Session {
  accountId: string;
  clientId: string;
  expiresAt: number;
  lastActivityAt: number;
  server: ReturnType<typeof createMcpServer>;
  transport: StreamableHTTPServerTransport;
  inactivityTimer: NodeJS.Timeout;
  expiryTimer: NodeJS.Timeout;
}

interface McpTransportDependencies {
  verifier: OAuthTokenVerifier;
  resourceMetadataUrl: URL;
  now?: () => number;
  maximumTotalSessions?: number;
  maximumSessionsPerAuthority?: number;
  maximumInitializationsInFlight?: number;
  initializationsPerWindow?: number;
  initializationWindowMs?: number;
}

export interface McpTransportController {
  authenticate: RequestHandler;
  handle: RequestHandler;
  closeAllSessions(): Promise<number>;
}

function isInitializeRequest(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    !Array.isArray(body) &&
    (body as { method?: unknown }).method === "initialize"
  );
}

export function createMcpTransportController({
  verifier,
  resourceMetadataUrl,
  now = Date.now,
  maximumTotalSessions = defaultMaximumTotalSessions,
  maximumSessionsPerAuthority = defaultMaximumSessionsPerAuthority,
  maximumInitializationsInFlight =
    defaultMaximumInitializationsInFlight,
  initializationsPerWindow = defaultInitializationsPerWindow,
  initializationWindowMs = defaultInitializationWindowMs,
}: McpTransportDependencies): McpTransportController {
  if (
    [
      maximumTotalSessions,
      maximumSessionsPerAuthority,
      maximumInitializationsInFlight,
      initializationsPerWindow,
      initializationWindowMs,
    ].some((value) => !Number.isSafeInteger(value) || value < 1)
  ) {
    throw new Error("invalid MCP transport limits");
  }
  const sessions = new Map<string, Session>();
  const initializationsInFlight = new Set<Promise<void>>();
  const initializationReservations = new Map<string, number>();
  let totalInitializationReservations = 0;
  const initializationLimiter = createIpRateLimiter({
    limit: initializationsPerWindow,
    windowMs: initializationWindowMs,
    now,
  });
  let closing = false;

  const authorityKey = (accountId: string, clientId: string): string =>
    `${accountId}\u0000${clientId}`;

  const authoritySessionCount = (
    accountId: string,
    clientId: string,
  ): number => {
    let count = 0;
    for (const session of sessions.values()) {
      if (
        session.accountId === accountId &&
        session.clientId === clientId
      ) {
        count += 1;
      }
    }
    return count;
  };

  const closeSession = async (sessionId: string): Promise<boolean> => {
    const session = sessions.get(sessionId);
    if (session === undefined) {
      return false;
    }
    sessions.delete(sessionId);
    clearTimeout(session.inactivityTimer);
    clearTimeout(session.expiryTimer);
    await session.server.close();
    return true;
  };

  const resetInactivity = (sessionId: string, session: Session): void => {
    clearTimeout(session.inactivityTimer);
    session.inactivityTimer = setTimeout(() => {
      void closeSession(sessionId);
    }, sessionInactivityMs);
  };

  const closeAllSessions = async (): Promise<number> => {
    closing = true;
    let closed = 0;
    const closeCurrentSessions = async (): Promise<void> => {
      const results = await Promise.all(
        [...sessions.keys()].map(closeSession),
      );
      closed += results.filter(Boolean).length;
    };

    await closeCurrentSessions();
    while (initializationsInFlight.size > 0) {
      await Promise.allSettled([...initializationsInFlight]);
      await closeCurrentSessions();
    }
    return closed;
  };

  const authenticate = requireBearerAuth({
    verifier,
    requiredScopes: [],
    resourceMetadataUrl: resourceMetadataUrl.href,
  });

  const handle: RequestHandler = async (request, response) => {
    const authInfo = request.auth;
    if (authInfo === undefined) {
      response.sendStatus(401);
      return;
    }

    let account;
    try {
      account = requireAccountContext(authInfo);
    } catch {
      response.set(
        "WWW-Authenticate",
        `Bearer error="insufficient_scope", error_description="Insufficient scope", scope="mail.read mail.send mail.organize", resource_metadata="${resourceMetadataUrl.href}"`,
      );
      response.status(403).json({ error: "insufficient_scope" });
      return;
    }

    const sessionId = request.header("mcp-session-id");
    if (sessionId !== undefined) {
      const session = sessions.get(sessionId);
      if (session === undefined) {
        response.status(404).json({ error: "session_not_found" });
        return;
      }
      const requestTime = now();
      if (
        requestTime >= session.expiresAt * 1_000 ||
        requestTime - session.lastActivityAt >= sessionInactivityMs
      ) {
        await closeSession(sessionId);
        response.status(404).json({ error: "session_not_found" });
        return;
      }
      if (
        session.accountId !== account.accountId ||
        session.clientId !== account.clientId
      ) {
        await closeSession(sessionId);
        response.status(403).json({ error: "session_forbidden" });
        return;
      }
      session.lastActivityAt = requestTime;
      resetInactivity(sessionId, session);
      await session.transport.handleRequest(request, response, request.body);
      return;
    }

    if (request.method !== "POST" || !isInitializeRequest(request.body)) {
      response.status(400).json({ error: "invalid_request" });
      return;
    }
    if (closing) {
      response.status(503).json({ error: "server_shutting_down" });
      return;
    }

    const currentAuthorityKey = authorityKey(
      account.accountId,
      account.clientId,
    );
    if (
      sessions.size + totalInitializationReservations >=
      maximumTotalSessions
    ) {
      response.set("Retry-After", capacityRetryAfterSeconds.toString());
      response.status(503).json({ error: "session_capacity_exhausted" });
      return;
    }
    if (
      authoritySessionCount(account.accountId, account.clientId) +
        (initializationReservations.get(currentAuthorityKey) ?? 0) >=
      maximumSessionsPerAuthority
    ) {
      response.set("Retry-After", capacityRetryAfterSeconds.toString());
      response.status(429).json({
        error: "authority_session_capacity_exhausted",
      });
      return;
    }
    if (
      initializationsInFlight.size >=
      maximumInitializationsInFlight
    ) {
      response.set("Retry-After", capacityRetryAfterSeconds.toString());
      response.status(503).json({
        error: "initialization_capacity_exhausted",
      });
      return;
    }
    const rateLimit = initializationLimiter.consume(currentAuthorityKey);
    if (!rateLimit.allowed) {
      response.set("Retry-After", rateLimit.retryAfter.toString());
      response.status(429).json({
        error: "initialization_rate_limited",
      });
      return;
    }

    totalInitializationReservations += 1;
    initializationReservations.set(
      currentAuthorityKey,
      (initializationReservations.get(currentAuthorityKey) ?? 0) + 1,
    );
    let reservationActive = true;
    const releaseReservation = (): void => {
      if (!reservationActive) {
        return;
      }
      reservationActive = false;
      totalInitializationReservations -= 1;
      const authorityReservations =
        initializationReservations.get(currentAuthorityKey) ?? 0;
      if (authorityReservations <= 1) {
        initializationReservations.delete(currentAuthorityKey);
      } else {
        initializationReservations.set(
          currentAuthorityKey,
          authorityReservations - 1,
        );
      }
    };

    try {
      const server = createMcpServer(account);
      let transport: StreamableHTTPServerTransport;
      transport = new StreamableHTTPServerTransport({
        enableJsonResponse: true,
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          releaseReservation();
          const initializedAt = now();
          const expiresInMs = Math.max(
            0,
            account.tokenExpiresAt * 1_000 - initializedAt,
          );
          const session: Session = {
            accountId: account.accountId,
            clientId: account.clientId,
            expiresAt: account.tokenExpiresAt,
            lastActivityAt: initializedAt,
            server,
            transport,
            inactivityTimer: setTimeout(() => {
              void closeSession(newSessionId);
            }, sessionInactivityMs),
            expiryTimer: setTimeout(() => {
              void closeSession(newSessionId);
            }, expiresInMs),
          };
          sessions.set(newSessionId, session);
        },
        onsessionclosed: async (closedSessionId) => {
          await closeSession(closedSessionId);
        },
      });
      transport.onclose = () => {
        const activeSessionId = transport.sessionId;
        if (activeSessionId !== undefined) {
          const session = sessions.get(activeSessionId);
          if (session !== undefined) {
            sessions.delete(activeSessionId);
            clearTimeout(session.inactivityTimer);
            clearTimeout(session.expiryTimer);
          }
        }
      };

      const initialization = (async () => {
        await server.connect(transport);
        await transport.handleRequest(request, response, request.body);
      })();
      initializationsInFlight.add(initialization);
      try {
        await initialization;
      } finally {
        initializationsInFlight.delete(initialization);
      }
    } finally {
      releaseReservation();
    }
  };

  return { authenticate, handle, closeAllSessions };
}
