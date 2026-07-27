import type { AddressInfo } from "node:net";

import { describe, expect, test, vi } from "vitest";

import {
  accountRepository,
  authPath,
  client,
  distinctLoginPages,
  hidden,
  HttpClient,
  installInteractionsFixture,
  interactionState,
  locationPath,
  loginPage,
  loginPageFor,
  pool,
  provider,
  reachConsent,
  reachConsentFor,
  registerClient,
  server,
  startApp,
  submitLogin,
} from "./support/interactions-fixture.js";

describe("mailcow app-password interactions", () => {
  installInteractionsFixture();

  test("renders a secret-free login and completes both-protocol authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    expect(login.response.headers["content-security-policy"]).toContain(
      "default-src 'none'",
    );
    expect(login.response.headers["cache-control"]).toContain("no-store");
    expect(login.response.body).toContain("dedicated mailcow app password");
    expect(login.response.body).toContain("IMAP and SMTP");
    expect(login.response.body).toContain(
      "cannot distinguish it from your primary password",
    );
    const cookies = login.response.headers["set-cookie"] ?? [];
    expect(cookies).toHaveLength(1);
    expect(cookies[0]).toMatch(
      /^mailcow_mcp_interaction_csrf=[^;]+; Path=\/mcp-login; HttpOnly; Secure; SameSite=Lax$/u,
    );

    const submitted = await submitLogin(
      login.path,
      login.response,
      "User@EXAMPLE.TEST",
      "a<&secret-password",
    );

    expect(submitted.status).toBe(303);
    expect(interactionState.protocolAttempts).toEqual([
      {
        mailbox: "User@example.test",
        password: "a<&secret-password",
      },
    ]);
    expect(login.response.body).not.toContain("a<&secret-password");
    expect(submitted.body).not.toContain("a<&secret-password");
  });

  test("rejects CSRF and protocol failures with generic secret-free responses", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    const csrfRejected = await client.postForm(login.path, {
      csrf: "tampered",
      mailbox: "user@example.test",
      app_password: "csrf-secret",
    });
    expect(csrfRejected.status).toBe(403);
    expect(csrfRejected.headers["cache-control"]).toContain("no-store");
    expect(interactionState.protocolAttempts).toHaveLength(0);

    interactionState.authenticationFailure = true;
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "authentication-secret",
    );
    expect(rejected.status).toBe(401);
    expect(rejected.body).toContain("Authentication failed");
    const observable = `${rejected.body}\n${JSON.stringify(errorSpy.mock.calls)}`;
    expect(observable).not.toContain("authentication-secret");
    expect(observable).not.toContain("protocol rejected");
    errorSpy.mockRestore();
  });

  test("blocks the sixth failure by source IP before rotating mailbox attempts", async () => {
    interactionState.authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "x-forwarded-for": "198.51.100.10, 203.0.113.50",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        `user${attempt}@example.test`,
        "bad-password",
        forwarded,
      );
      expect(response.status).toBe(401);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "another@example.test",
      "bad-password",
      forwarded,
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(5);
  });

  test("blocks the sixth failure by canonical mailbox across rotating IPs", async () => {
    interactionState.authenticationFailure = true;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        attempt % 2 === 0 ? "USER@EXAMPLE.TEST" : "user@example.test",
        "bad-password",
        {
          "x-forwarded-for": `198.51.100.10, 203.0.113.${attempt}`,
        },
      );
      expect(response.status).toBe(401);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "User@example.test",
      "bad-password",
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.99",
      },
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(5);
  });

  test("atomically caps concurrent protocol verification by source IP across distinct interactions", async () => {
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 6);
    interactionState.verificationDelayMs = 200;

    const firstFive = logins
      .slice(0, 5)
      .map(({ client: loginClient, path, response }, index) =>
        loginClient.postForm(
          path,
          {
            csrf: hidden(response.body, "csrf"),
            mailbox: `user${index}@example.test`,
            app_password: "app-password",
          },
          {
            "x-forwarded-for": "198.51.100.10, 203.0.113.80",
          },
        ),
      );
    await new Promise<void>((resolve) => {
      if (interactionState.protocolAttempts.length === 5) {
        resolve();
        return;
      }
      interactionState.verificationStarted = () => {
        if (interactionState.protocolAttempts.length === 5) {
          resolve();
        }
      };
    });
    const sixth = logins[5]!;
    const rejected = await sixth.client.postForm(
      sixth.path,
      {
        csrf: hidden(sixth.response.body, "csrf"),
        mailbox: "user5@example.test",
        app_password: "app-password",
      },
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.80",
      },
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(5);
    expect(
      (await Promise.all(firstFive)).map((response) => response.status),
    ).toEqual([303, 303, 303, 303, 303]);
  });

  test("atomically caps concurrent protocol verification by mailbox across distinct IPs", async () => {
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 6);
    interactionState.verificationDelayMs = 200;

    const firstFive = logins
      .slice(0, 5)
      .map(({ client: loginClient, path, response }, index) =>
        loginClient.postForm(
          path,
          {
            csrf: hidden(response.body, "csrf"),
            mailbox:
              index % 2 === 0 ? "USER@EXAMPLE.TEST" : "user@example.test",
            app_password: "app-password",
          },
          {
            "x-forwarded-for": `198.51.100.10, 203.0.113.${90 + index}`,
          },
        ),
      );
    await new Promise<void>((resolve) => {
      if (interactionState.protocolAttempts.length === 5) {
        resolve();
        return;
      }
      interactionState.verificationStarted = () => {
        if (interactionState.protocolAttempts.length === 5) {
          resolve();
        }
      };
    });
    const sixth = logins[5]!;
    const rejected = await sixth.client.postForm(
      sixth.path,
      {
        csrf: hidden(sixth.response.body, "csrf"),
        mailbox: "User@example.test",
        app_password: "app-password",
      },
      {
        "x-forwarded-for": "198.51.100.10, 203.0.113.99",
      },
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(5);
    expect(
      (await Promise.all(firstFive)).map((response) => response.status),
    ).toEqual([303, 303, 303, 303, 303]);
  });

  test("fails closed when the bounded interaction lock is full", async () => {
    await startApp({ maximumInFlightInteractions: 1 });
    const clientId = await registerClient();
    const logins = await distinctLoginPages(clientId, 2);
    interactionState.verificationDelayMs = 200;
    const started = new Promise<void>((resolve) => {
      interactionState.verificationStarted = resolve;
    });
    const first = logins[0]!.client.postForm(logins[0]!.path, {
      csrf: hidden(logins[0]!.response.body, "csrf"),
      mailbox: "first@example.test",
      app_password: "app-password",
    });
    await started;
    const rejected = await logins[1]!.client.postForm(logins[1]!.path, {
      csrf: hidden(logins[1]!.response.body, "csrf"),
      mailbox: "second@example.test",
      app_password: "app-password",
    });

    expect(rejected.status).toBe(503);
    expect(interactionState.protocolAttempts).toHaveLength(1);
    expect((await first).status).toBe(303);
  });

  test("times out protocol verification and releases the interaction lock", async () => {
    await startApp({ verificationTimeoutMs: 25 });
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    interactionState.verificationDelayMs = 100;

    const timedOut = await submitLogin(login.path, login.response);
    expect(timedOut.status).toBe(401);

    interactionState.verificationDelayMs = 0;
    const retried = await submitLogin(login.path, login.response);
    expect(retried.status).toBe(303);
    expect(interactionState.protocolAttempts).toHaveLength(2);
  });

  test("does not poison authentication quotas after repository failures", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const originalUpsert =
      accountRepository.upsertVerifiedForAuthorization.bind(
        accountRepository,
      );
    let failures = 0;
    const upsert = vi
      .spyOn(accountRepository, "upsertVerifiedForAuthorization")
      .mockImplementation(async (mailbox, password) => {
        if (failures < 5) {
          failures += 1;
          throw new Error(`database rejected ${mailbox} ${password}`);
        }
        return originalUpsert(mailbox, password);
      });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        "user@example.test",
        "operational-secret",
      );
      expect(response.status).toBe(503);
      expect(response.headers["cache-control"]).toContain("no-store");
      expect(response.body).not.toContain("database rejected");
      expect(response.body).not.toContain("operational-secret");
    }
    const succeeded = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
    );

    expect(succeeded.status).toBe(303);
    expect(interactionState.protocolAttempts).toHaveLength(6);
    upsert.mockRestore();
  });

  test("does not poison authentication quotas after provider failures", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const originalFinished = provider.interactionFinished.bind(provider);
    let failures = 0;
    const finished = vi
      .spyOn(provider, "interactionFinished")
      .mockImplementation(async (...args) => {
        if (failures < 5) {
          failures += 1;
          throw new Error("provider unavailable");
        }
        return originalFinished(...args);
      });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await submitLogin(
        login.path,
        login.response,
        "user@example.test",
        "operational-secret",
      );
      expect(response.status).toBe(503);
      expect(response.headers["cache-control"]).toContain("no-store");
      expect(response.body).not.toContain("provider unavailable");
      expect(response.body).not.toContain("operational-secret");
    }
    const succeeded = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
    );

    expect(succeeded.status).toBe(303);
    expect(interactionState.protocolAttempts).toHaveLength(6);
    finished.mockRestore();
  });

  test("counts oversized login bodies against the source quota before authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "content-type": "application/x-www-form-urlencoded",
      "x-forwarded-for": "198.51.100.10, 203.0.113.70",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await client.request(login.path, {
        method: "POST",
        headers: forwarded,
        body: `padding=${"x".repeat(20 * 1_024)}`,
      });
      expect(response.status).toBe(413);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
      forwarded,
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(0);
  });

  test("counts malformed login bodies against the source quota before authentication", async () => {
    const clientId = await registerClient();
    const login = await loginPage(clientId);
    const forwarded = {
      "content-type": "application/json",
      "x-forwarded-for": "198.51.100.10, 203.0.113.71",
    };

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await client.request(login.path, {
        method: "POST",
        headers: forwarded,
        body: "{",
      });
      expect(response.status).toBe(403);
    }
    const rejected = await submitLogin(
      login.path,
      login.response,
      "user@example.test",
      "app-password",
      {
        "x-forwarded-for": forwarded["x-forwarded-for"],
      },
    );

    expect(rejected.status).toBe(429);
    expect(interactionState.protocolAttempts).toHaveLength(0);
  });

  test("rejects a provider interaction with an unallowlisted return URL", async () => {
    const details = provider.interactionDetails.bind(provider);
    vi.spyOn(provider, "interactionDetails").mockImplementationOnce(
      async (request, response) => ({
        ...(await details(request, response)),
        returnTo: "https://evil.example/oauth/resume",
      }),
    );
    const clientId = await registerClient();
    const started = await client.get(authPath(clientId, "mail.read"));
    const response = await client.get(locationPath(started));

    expect(response.status).toBe(400);
    expect(response.body).not.toContain("evil.example");
  });

  test("allows only one parallel login submission for an interaction", async () => {
    let release: (() => void) | undefined;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const startedVerification = new Promise<void>((resolve) => {
      const original = interactionState.protocolAttempts.push.bind(
        interactionState.protocolAttempts,
      );
      interactionState.protocolAttempts.push = (...values) => {
        const result = original(...values);
        resolve();
        return result;
      };
    });
    interactionState.authenticationFailure = false;
    const originalVerifier = provider;
    void originalVerifier;
    const clientId = await registerClient();
    const login = await loginPage(clientId);

    // Delay the repository path without changing the external protocol fake.
    const execute = pool.execute.bind(pool);
    const executeSpy = vi
      .spyOn(pool, "execute")
      .mockImplementation(async (...args: Parameters<typeof pool.execute>) => {
        if (
          typeof args[0] === "string" &&
          args[0].includes("INSERT INTO accounts")
        ) {
          await waiting;
        }
        return execute(...args);
      });
    const first = submitLogin(login.path, login.response);
    await startedVerification;
    const duplicate = await submitLogin(login.path, login.response);
    release?.();
    const [firstResponse, duplicateResponse] = await Promise.all([
      first,
      duplicate,
    ]);

    expect([firstResponse.status, duplicateResponse.status].sort()).toEqual([
      303, 409,
    ]);
    executeSpy.mockRestore();
  });
});
