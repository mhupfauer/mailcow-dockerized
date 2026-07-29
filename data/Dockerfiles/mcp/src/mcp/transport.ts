import { randomUUID } from "node:crypto";

import type { RequestHandler } from "express";

import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { requireAccountContext } from "./context.js";
import { createMcpServer } from "./server.js";

const sessionInactivityMs = 30 * 60 * 1_000;

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
}

export interface McpTransportController {
  authenticate: RequestHandler;
  handle: RequestHandler;
  closeAllSessions(): Promise<void>;
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
}: McpTransportDependencies): McpTransportController {
  const sessions = new Map<string, Session>();

  const closeSession = async (sessionId: string): Promise<void> => {
    const session = sessions.get(sessionId);
    if (session === undefined) {
      return;
    }
    sessions.delete(sessionId);
    clearTimeout(session.inactivityTimer);
    clearTimeout(session.expiryTimer);
    await session.server.close();
  };

  const resetInactivity = (sessionId: string, session: Session): void => {
    clearTimeout(session.inactivityTimer);
    session.inactivityTimer = setTimeout(() => {
      void closeSession(sessionId);
    }, sessionInactivityMs);
  };

  const closeAllSessions = async (): Promise<void> => {
    await Promise.all([...sessions.keys()].map(closeSession));
  };

  const authenticate = requireBearerAuth({
    verifier,
    requiredScopes: ["mail.read"],
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
      account = requireAccountContext(authInfo, "mail.read");
    } catch {
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

    const server = createMcpServer(account);
    let transport: StreamableHTTPServerTransport;
    transport = new StreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (newSessionId) => {
        const initializedAt = now();
        const expiresInMs = Math.max(
          0,
          authInfo.expiresAt! * 1_000 - initializedAt,
        );
        const session: Session = {
          accountId: account.accountId,
          clientId: account.clientId,
          expiresAt: authInfo.expiresAt!,
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
      onsessionclosed: (closedSessionId) => closeSession(closedSessionId),
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

    await server.connect(transport);
    await transport.handleRequest(request, response, request.body);
  };

  return { authenticate, handle, closeAllSessions };
}
