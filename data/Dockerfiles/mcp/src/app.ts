import express, { type Express } from "express";
import type { Provider } from "oidc-provider";

interface AppDependencies {
  readiness(): Promise<boolean>;
  resourceMetadataUrl: URL;
  oidcProvider?: Provider;
}

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

  app.post("/mcp", (_request, response) => {
    response.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${deps.resourceMetadataUrl.href}"`,
    );
    response.sendStatus(401);
  });

  if (deps.oidcProvider !== undefined) {
    deps.oidcProvider.proxy = true;
    deps.oidcProvider.maxIpsCount = 1;
    app.post(
      "/oauth/reg",
      express.json({ limit: "56kb", strict: true }),
      (_request, _response, next) => next(),
    );
    app.use(deps.oidcProvider.callback());
  }

  return app;
}
