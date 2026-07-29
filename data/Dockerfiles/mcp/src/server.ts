import type { Server } from "node:http";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import type { Pool } from "mysql2/promise";

import { createApp } from "./app.js";
import { MariaDbAccountRepository } from "./auth/account-repository.js";
import {
  BoundedAuthorizationMutationCoordinator,
} from "./auth/authorization-state.js";
import { DualProtocolCredentialVerifier } from "./auth/credential-verifier.js";
import { AesGcmCredentialVault } from "./auth/crypto-vault.js";
import { createOidcProvider } from "./auth/oidc-provider.js";
import { loadConfig } from "./config.js";
import { createPool } from "./db/pool.js";

interface StartProductionServerOptions {
  port?: number;
}

export interface ProductionServer {
  server: Server;
  close(): Promise<void>;
}

function listen(
  app: ReturnType<typeof createApp>,
  port: number,
): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = app.listen(port);
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve(server);
    };
    server.once("error", onError);
    server.once("listening", onListening);
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function createClose(server: Server, pool: Pool): () => Promise<void> {
  let closing: Promise<void> | undefined;

  return () => {
    closing ??= (async () => {
      let serverError: Error | undefined;
      try {
        await closeServer(server);
      } catch (error) {
        serverError =
          error instanceof Error ? error : new Error("server close failed");
      }
      await pool.end();
      if (serverError !== undefined) {
        throw serverError;
      }
    })();
    return closing;
  };
}

export async function startProductionServer(
  env: NodeJS.ProcessEnv = process.env,
  options: StartProductionServerOptions = {},
): Promise<ProductionServer> {
  const config = loadConfig(env);
  const trustSource = await readFile(config.tlsTrustPath);
  const pool = createPool({
    host: config.db.host,
    port: config.db.port,
    database: config.db.name,
    user: config.db.user,
    password: config.db.password,
  });

  try {
    const oidcProvider = await createOidcProvider({
      pool,
      issuer: config.issuer,
      resource: config.resource,
      encryptionKey: config.encryptionKey,
      env,
    });
    const vault = new AesGcmCredentialVault(config.encryptionKey);
    const accountRepository = new MariaDbAccountRepository(pool, vault);
    const authorityMutations = new BoundedAuthorizationMutationCoordinator(
      1_000,
    );
    const credentialVerifier = new DualProtocolCredentialVerifier({
      hostname: config.hostname,
      ca: trustSource,
    });
    const app = createApp({
      readiness: async () => {
        await pool.query("SELECT 1");
        return true;
      },
      resourceMetadataUrl: config.resourceMetadataUrl,
      resource: config.resource,
      oidcProvider,
      registrationsPerHour: config.registrationsPerHour,
      interactions: {
        accountRepository,
        credentialVerifier,
        pool,
        issuer: config.issuer,
        resource: config.resource,
        encryptionKey: config.encryptionKey,
        loginAttempts: config.loginAttempts,
        loginWindowSeconds: config.loginWindowSeconds,
        authorityMutations,
      },
    });
    const server = await listen(app, options.port ?? config.port);

    return {
      server,
      close: createClose(server, pool),
    };
  } catch (error) {
    await pool.end();
    throw error;
  }
}

async function run(): Promise<void> {
  const production = await startProductionServer();
  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    void production.close().catch((error: unknown) => {
      console.error(error);
      process.exitCode = 1;
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  run().catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
