import express, { type Express } from "express";

interface AppDependencies {
  readiness(): Promise<boolean>;
  resourceMetadataUrl: URL;
}

export function createApp(deps: AppDependencies): Express {
  const app = express();

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

  return app;
}
