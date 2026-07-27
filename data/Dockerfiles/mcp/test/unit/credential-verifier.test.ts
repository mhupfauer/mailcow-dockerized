import { describe, expect, test, vi } from "vitest";

import {
  DualProtocolCredentialVerifier,
  createImapAuthenticator,
  createSmtpAuthenticator,
  type ProtocolCredentialOptions,
} from "../../src/auth/credential-verifier.js";

const ca = Buffer.from("test mailcow ca");
const mailbox = "user@example.test";
const appPassword = "app-password";

function verifier(
  imapAuthenticate: (options: ProtocolCredentialOptions) => Promise<void>,
  smtpAuthenticate: (options: ProtocolCredentialOptions) => Promise<void>,
): DualProtocolCredentialVerifier {
  return new DualProtocolCredentialVerifier({
    hostname: "mail.example.test",
    ca,
    imapAuthenticator: { authenticate: imapAuthenticate },
    smtpAuthenticator: { authenticate: smtpAuthenticate },
  });
}

describe("DualProtocolCredentialVerifier", () => {
  test("requires IMAP and SMTP with the reviewed credential and TLS options", async () => {
    const imapOptions: ProtocolCredentialOptions[] = [];
    const smtpOptions: ProtocolCredentialOptions[] = [];
    const subject = verifier(
      async (options) => {
        imapOptions.push(options);
      },
      async (options) => {
        smtpOptions.push(options);
      },
    );

    await subject.verify(mailbox, appPassword);

    expect(imapOptions).toEqual([
      {
        username: mailbox,
        password: appPassword,
        host: "dovecot-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
    ]);
    expect(smtpOptions).toEqual([
      {
        username: mailbox,
        password: appPassword,
        host: "postfix-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
    ]);
  });

  test("rejects generically and does not try SMTP when IMAP authentication fails", async () => {
    let smtpAttempts = 0;
    const subject = verifier(
      async () => {
        throw new Error(`IMAP rejected ${mailbox} ${appPassword}`);
      },
      async () => {
        smtpAttempts += 1;
      },
    );

    await expect(subject.verify(mailbox, appPassword)).rejects.toThrow(
      "mailbox authentication failed",
    );
    expect(smtpAttempts).toBe(0);
  });

  test("rejects generically when SMTP fails after IMAP succeeds", async () => {
    const subject = verifier(
      async () => undefined,
      async () => {
        throw new Error(`SMTP rejected ${mailbox} ${appPassword}`);
      },
    );

    await expect(subject.verify(mailbox, appPassword)).rejects.toThrow(
      "mailbox authentication failed",
    );
  });
});

describe("default protocol authenticators", () => {
  test("uses IMAP STARTTLS AUTH=PLAIN and closes after success", async () => {
    const connect = vi.fn(async () => undefined);
    const close = vi.fn();
    let actualOptions: Record<string, unknown> | undefined;
    const authenticator = createImapAuthenticator(ca, (options) => {
      actualOptions = options as unknown as Record<string, unknown>;
      return { connect, close };
    });

    await authenticator.authenticate({
      username: mailbox,
      password: appPassword,
      host: "dovecot-mailcow",
      servername: "mail.example.test",
      rejectUnauthorized: true,
      ca,
    });

    expect(actualOptions).toEqual({
      host: "dovecot-mailcow",
      port: 143,
      secure: false,
      doSTARTTLS: true,
      auth: {
        user: mailbox,
        pass: appPassword,
        loginMethod: "AUTH=PLAIN",
      },
      servername: "mail.example.test",
      tls: {
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
      logger: false,
      verifyOnly: true,
    });
    expect(connect).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  test("closes IMAP after a connection failure", async () => {
    const close = vi.fn();
    const authenticator = createImapAuthenticator(ca, () => ({
      connect: async () => {
        throw new Error("connection failed");
      },
      close,
    }));

    await expect(
      authenticator.authenticate({
        username: mailbox,
        password: appPassword,
        host: "dovecot-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      }),
    ).rejects.toThrow("connection failed");
    expect(close).toHaveBeenCalledOnce();
  });

  test("aborts and closes an in-progress IMAP connection", async () => {
    const controller = new AbortController();
    let rejectConnection: ((error: Error) => void) | undefined;
    const close = vi.fn(() => {
      rejectConnection?.(new Error("connection aborted"));
    });
    const authenticator = createImapAuthenticator(ca, () => ({
      connect: () =>
        new Promise<void>((_resolve, reject) => {
          rejectConnection = reject;
        }),
      close,
    }));

    const authenticating = authenticator.authenticate(
      {
        username: mailbox,
        password: appPassword,
        host: "dovecot-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
      controller.signal,
    );
    controller.abort();

    await expect(authenticating).rejects.toThrow("connection aborted");
    expect(close).toHaveBeenCalledOnce();
  });

  test("uses SMTP submission STARTTLS PLAIN and closes after verification", async () => {
    const verify = vi.fn(async () => true);
    const close = vi.fn();
    let actualOptions: Record<string, unknown> | undefined;
    const authenticator = createSmtpAuthenticator(ca, (options) => {
      actualOptions = options as unknown as Record<string, unknown>;
      return { verify, close };
    });

    await authenticator.authenticate({
      username: mailbox,
      password: appPassword,
      host: "postfix-mailcow",
      servername: "mail.example.test",
      rejectUnauthorized: true,
      ca,
    });

    expect(actualOptions).toEqual({
      host: "postfix-mailcow",
      port: 587,
      secure: false,
      requireTLS: true,
      auth: { user: mailbox, pass: appPassword },
      authMethod: "PLAIN",
      tls: {
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
    });
    expect(verify).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  test("closes SMTP after a verification failure", async () => {
    const close = vi.fn();
    const authenticator = createSmtpAuthenticator(ca, () => ({
      verify: async () => {
        throw new Error("verification failed");
      },
      close,
    }));

    await expect(
      authenticator.authenticate({
        username: mailbox,
        password: appPassword,
        host: "postfix-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      }),
    ).rejects.toThrow("verification failed");
    expect(close).toHaveBeenCalledOnce();
  });

  test("aborts and closes an in-progress SMTP verification", async () => {
    const controller = new AbortController();
    let rejectVerification: ((error: Error) => void) | undefined;
    const close = vi.fn(() => {
      rejectVerification?.(new Error("verification aborted"));
    });
    const authenticator = createSmtpAuthenticator(ca, () => ({
      verify: () =>
        new Promise<true>((_resolve, reject) => {
          rejectVerification = reject;
        }),
      close,
    }));

    const authenticating = authenticator.authenticate(
      {
        username: mailbox,
        password: appPassword,
        host: "postfix-mailcow",
        servername: "mail.example.test",
        rejectUnauthorized: true,
        ca,
      },
      controller.signal,
    );
    controller.abort();

    await expect(authenticating).rejects.toThrow("verification aborted");
    expect(close).toHaveBeenCalledOnce();
  });
});
