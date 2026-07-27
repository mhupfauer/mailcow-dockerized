import { ImapFlow, type ImapFlowOptions } from "imapflow";
import nodemailer from "nodemailer";
import type SMTPTransport from "nodemailer/lib/smtp-transport/index.js";

export interface CredentialVerifier {
  verify(
    mailbox: string,
    appPassword: string,
    signal?: AbortSignal,
  ): Promise<void>;
}

export interface ProtocolCredentialOptions {
  username: string;
  password: string;
  host: string;
  servername: string;
  rejectUnauthorized: true;
  ca: Buffer;
}

export interface CredentialAuthenticator {
  authenticate(
    options: ProtocolCredentialOptions,
    signal?: AbortSignal,
  ): Promise<void>;
}

interface ImapClient {
  connect(): Promise<void>;
  close(): void;
}

interface SmtpTransport {
  verify(): Promise<true> | Promise<boolean>;
  close(): void;
}

type ImapClientFactory = (options: ImapFlowOptions) => ImapClient;
type SmtpTransportFactory = (
  options: SMTPTransport.Options,
) => SmtpTransport;

interface DualProtocolCredentialVerifierOptions {
  hostname: string;
  ca: Buffer;
  imapAuthenticator?: CredentialAuthenticator;
  smtpAuthenticator?: CredentialAuthenticator;
}

export function createImapAuthenticator(
  trustSource: Buffer,
  createClient: ImapClientFactory = (options) => new ImapFlow(options),
): CredentialAuthenticator {
  return {
    async authenticate(options, signal) {
      signal?.throwIfAborted();
      const client = createClient({
        host: options.host,
        port: 143,
        secure: false,
        doSTARTTLS: true,
        auth: {
          user: options.username,
          pass: options.password,
          loginMethod: "AUTH=PLAIN",
        },
        servername: options.servername,
        tls: {
          servername: options.servername,
          rejectUnauthorized: options.rejectUnauthorized,
          ca: trustSource,
        },
        logger: false,
        verifyOnly: true,
      });
      let closed = false;
      const close = () => {
        if (!closed) {
          closed = true;
          client.close();
        }
      };
      signal?.addEventListener("abort", close, { once: true });

      try {
        await client.connect();
      } finally {
        signal?.removeEventListener("abort", close);
        close();
      }
    },
  };
}

export function createSmtpAuthenticator(
  trustSource: Buffer,
  createTransport: SmtpTransportFactory = (options) =>
    nodemailer.createTransport(options),
): CredentialAuthenticator {
  return {
    async authenticate(options, signal) {
      signal?.throwIfAborted();
      const transport = createTransport({
        host: options.host,
        port: 587,
        secure: false,
        requireTLS: true,
        auth: {
          user: options.username,
          pass: options.password,
        },
        authMethod: "PLAIN",
        tls: {
          servername: options.servername,
          rejectUnauthorized: options.rejectUnauthorized,
          ca: trustSource,
        },
      });
      let closed = false;
      const close = () => {
        if (!closed) {
          closed = true;
          transport.close();
        }
      };
      signal?.addEventListener("abort", close, { once: true });

      try {
        await transport.verify();
      } finally {
        signal?.removeEventListener("abort", close);
        close();
      }
    },
  };
}

export class DualProtocolCredentialVerifier implements CredentialVerifier {
  private readonly imapAuthenticator: CredentialAuthenticator;
  private readonly smtpAuthenticator: CredentialAuthenticator;

  constructor(
    private readonly options: DualProtocolCredentialVerifierOptions,
  ) {
    this.imapAuthenticator =
      options.imapAuthenticator ?? createImapAuthenticator(options.ca);
    this.smtpAuthenticator =
      options.smtpAuthenticator ?? createSmtpAuthenticator(options.ca);
  }

  async verify(
    mailbox: string,
    appPassword: string,
    signal?: AbortSignal,
  ): Promise<void> {
    try {
      await this.imapAuthenticator.authenticate({
        username: mailbox,
        password: appPassword,
        host: "dovecot-mailcow",
        servername: this.options.hostname,
        rejectUnauthorized: true,
        ca: this.options.ca,
      }, signal);
      await this.smtpAuthenticator.authenticate({
        username: mailbox,
        password: appPassword,
        host: "postfix-mailcow",
        servername: this.options.hostname,
        rejectUnauthorized: true,
        ca: this.options.ca,
      }, signal);
    } catch {
      throw new Error("mailbox authentication failed");
    }
  }
}
