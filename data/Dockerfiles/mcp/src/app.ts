import express, { type Express } from "express";

export function createApp(deps: { readiness(): Promise<boolean> }): Express {
  const app = express();

  app.get("/health/live", (_request, response) => {
    response.status(200).json({ status: "live" });
  });

  app.get("/health/ready", async (_request, response) => {
    const ready = await deps.readiness();
    response.sendStatus(ready ? 200 : 503);
  });

  app.post("/mcp", (request, response) => {
    const host = request.get("host") ?? "localhost";
    response.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="https://${host}/.well-known/oauth-protected-resource/mcp"`,
    );
    response.sendStatus(401);
  });

  return app;
}
