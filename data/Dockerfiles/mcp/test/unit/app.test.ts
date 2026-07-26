import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, test } from "vitest";

import { createApp } from "../../src/app.js";

async function request(
  app: ReturnType<typeof createApp>,
  path: string,
  method = "GET",
  headers?: Record<string, string>,
) {
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));

  try {
    const address = server.address() as AddressInfo;
    return await new Promise<{
      status: number;
      headers: Record<string, string | string[] | undefined>;
      json(): unknown;
    }>((resolve, reject) => {
      const clientRequest = httpRequest(
        {
          host: "127.0.0.1",
          port: address.port,
          path,
          method,
          headers,
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () => {
            const body = Buffer.concat(chunks).toString("utf8");
            resolve({
              status: response.statusCode ?? 0,
              headers: response.headers,
              json: () => JSON.parse(body),
            });
          });
        },
      );

      clientRequest.on("error", reject);
      clientRequest.end();
    });
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

describe("createApp", () => {
  test("reports a live process", async () => {
    const response = await request(
      createApp({
        readiness: async () => false,
        resourceMetadataUrl: new URL(
          "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
        ),
      }),
      "/health/live",
    );

    expect(response.status).toBe(200);
    expect(response.json()).toEqual({ status: "live" });
  });

  test("reports ready when its readiness dependency resolves true", async () => {
    const response = await request(
      createApp({
        readiness: async () => true,
        resourceMetadataUrl: new URL(
          "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
        ),
      }),
      "/health/ready",
    );

    expect(response.status).toBe(200);
  });

  test("reports unavailable when its readiness dependency resolves false", async () => {
    const response = await request(
      createApp({
        readiness: async () => false,
        resourceMetadataUrl: new URL(
          "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
        ),
      }),
      "/health/ready",
    );

    expect(response.status).toBe(503);
  });

  test("reports unavailable when its readiness dependency rejects", async () => {
    const response = await request(
      createApp({
        readiness: async () => {
          throw new Error("database unavailable");
        },
        resourceMetadataUrl: new URL(
          "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
        ),
      }),
      "/health/ready",
    );

    expect(response.status).toBe(503);
  });

  test("challenges unauthenticated MCP posts with configured metadata despite a hostile Host", async () => {
    const response = await request(
      createApp({
        readiness: async () => true,
        resourceMetadataUrl: new URL(
          "https://mail.example.test/.well-known/oauth-protected-resource/mcp",
        ),
      }),
      "/mcp",
      "POST",
      { host: "attacker.example.test" },
    );

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(
      'Bearer resource_metadata="https://mail.example.test/.well-known/oauth-protected-resource/mcp"',
    );
  });
});
