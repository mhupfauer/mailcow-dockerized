import express, {
  type ErrorRequestHandler,
  type Express,
  type RequestHandler,
} from "express";
import type { Provider } from "oidc-provider";

import {
  createInteractionRouter,
  type InteractionDependencies,
} from "./auth/interactions.js";
import { AccessTokenVerifier } from "./auth/token-verifier.js";
import { createIpRateLimiter } from "./http/rate-limit.js";
import { createMcpMetadataRouter } from "./http/metadata.js";
import { createMcpTransportRouter } from "./mcp/transport.js";

interface AppDependencies {
  readiness(): Promise<boolean>;
  resource?: URL;
  resourceMetadataUrl: URL;
  oidcProvider?: Provider;
  registrationsPerHour?: number;
  interactions?: Omit<InteractionDependencies, "provider">;
}

const registrationPath = "/oauth/reg";
const registrationWindowMs = 60 * 60 * 1_000;

export function createApp(deps: AppDependencies): Express {
  const app = express();
  app.set("trust proxy", 1);

  app.get("/health/live", (_request, response) => {
    response.status(200).json({ status: "live" });
  });

  app.get("/health/ready", async (_request, response) => {
    try {
      response.sendStatus((await deps.readiness()) ? 200 : 503);
    } catch {
      response.sendStatus(503);
    }
  });

  if (deps.oidcProvider !== undefined && deps.resource !== undefined) {
    app.use(
      createMcpMetadataRouter({
        issuer: new URL(deps.oidcProvider.issuer),
        resource: deps.resource,
      }),
    );
    app.all(
      "/mcp",
      express.json({ strict: true }),
      ...createMcpTransportRouter({
        verifier: new AccessTokenVerifier({
          provider: deps.oidcProvider,
          resource: deps.resource,
        }),
        resourceMetadataUrl: deps.resourceMetadataUrl,
      }),
    );
  } else {
    app.post("/mcp", (_request, response) => {
      response.set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${deps.resourceMetadataUrl.href}"`,
      );
      response.sendStatus(401);
    });
  }

  if (deps.oidcProvider !== undefined) {
    deps.oidcProvider.proxy = true;
    deps.oidcProvider.maxIpsCount = 1;
    const registrationLimiter = createIpRateLimiter({
      limit: deps.registrationsPerHour ?? 10,
      windowMs: registrationWindowMs,
    });
    const limitRegistration: RequestHandler = (request, response, next) => {
      const decision = registrationLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? "",
      );
      if (decision.allowed) {
        next();
        return;
      }
      response.set("Retry-After", decision.retryAfter.toString());
      response.status(429).json({
        error: "too_many_requests",
        error_description: "registration rate limit exceeded",
      });
    };
    const normalizeRegistrationBodyError: ErrorRequestHandler = (
      error,
      _request,
      response,
      _next,
    ) => {
      const status =
        typeof error === "object" &&
        error !== null &&
        "status" in error &&
        error.status === 413
          ? 413
          : 400;
      response.status(status).json({
        error: "invalid_client_metadata",
        error_description:
          status === 413
            ? "registration body is too large"
            : "registration body is invalid",
      });
    };
    const continueToProvider: RequestHandler = (
      _request,
      _response,
      next,
    ) => next();
    app.post(
      registrationPath,
      limitRegistration,
      express.json({ limit: "56kb", strict: true }),
      continueToProvider,
      normalizeRegistrationBodyError,
    );
    if (deps.interactions !== undefined) {
      app.use(
        createInteractionRouter({
          ...deps.interactions,
          provider: deps.oidcProvider,
        }),
      );
    }
    app.use(deps.oidcProvider.callback());
  }

  return app;
}
