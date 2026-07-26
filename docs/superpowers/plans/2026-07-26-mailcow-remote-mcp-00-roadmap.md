# Mailcow Remote MCP Implementation Plan Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a disabled-by-default, remotely hosted MCP service that mailcow
users authorize with IMAP/SMTP-scoped app passwords and that safely survives
normal mailcow updates.

**Architecture:** Implement the service as an ESM TypeScript application and
publish it as a pinned `ghcr.io/mailcow/mcp:0.1.0` image. Mailcow's tracked
Compose file exposes it only through the `mcp` profile, nginx conditionally
routes the public endpoints, and the existing MariaDB stores OAuth and account
state. The work is split into four dependent plans so each review gate produces
a testable increment.

**Tech Stack:** Node.js 24.18 LTS, TypeScript 7.0, Express 5,
`@modelcontextprotocol/sdk` 1.29, `oidc-provider` 9.10, MariaDB/mysql2,
ImapFlow, Nodemailer, Vitest, Docker Compose, Bash, Python/Jinja nginx
bootstrap.

## Global Constraints

- The service endpoint is `https://${MAILCOW_HOSTNAME}/mcp`; no application
  port is published on the host.
- Use MCP specification revision `2025-11-25` and stable
  `@modelcontextprotocol/sdk@1.29.0`; do not adopt the v2 beta during version
  one.
- Use `oidc-provider@9.10.0`, authorization code plus refresh token grants only,
  mandatory PKCE-S256, opaque 15-minute access tokens, and rotating refresh
  tokens with a 30-day maximum lifetime.
- The OAuth resource and audience are exactly
  `https://${MAILCOW_HOSTNAME}/mcp`; scopes are exactly `mail.read`,
  `mail.send`, and `mail.organize`.
- A mailbox is selected only from authenticated token state. No tool input may
  select an email account.
- Store the 32-byte `MCP_ENCRYPTION_KEY` and 32-byte `MCP_DBPASS` as 64
  hexadecimal characters in mode-`0600` `mailcow.conf`; never log them.
- Once `MCP_CONFIG_VERSION=1` exists, never silently regenerate either secret.
- Use AES-256-GCM with a new 96-bit nonce and record/account-bound AAD for
  credentials, signing keys, handles, and staged attachment files.
- Long-running `mcp-mailcow` receives only its dedicated MariaDB credentials;
  only the one-shot initializer receives `DBROOT`.
- Pre-existing and new installations remain disabled unless
  `COMPOSE_PROFILES` contains the exact comma-separated token `mcp`.
- `update.sh --force` and `--skip-start` never enable MCP.
- MCP failures must not prevent SMTP, IMAP, nginx's normal routes, or the
  mailcow UI from starting.
- No permanent message deletion, IMAP expunge, administrator access,
  cross-mailbox access, alias sending, arbitrary URL attachments, or attachment
  execution.
- Default attachment limits are 10 MiB per attachment, 25 MiB encoded message,
  1 MiB decoded base64 tool input, and one-hour upload lifetime.
- Commit after every task only when the task's focused tests and the phase
  verification command pass.

## Plan Order

1. [Phase 1: Deployment and update
   foundation](2026-07-26-mailcow-remote-mcp-01-deployment.md)
2. [Phase 2: OAuth, identity, and
   persistence](2026-07-26-mailcow-remote-mcp-02-oauth.md)
3. [Phase 3: Mailbox and send
   tools](2026-07-26-mailcow-remote-mcp-03-mail-tools.md)
4. [Phase 4: Attachments, MCP App, and release
   hardening](2026-07-26-mailcow-remote-mcp-04-attachments-release.md)

Do not start a phase until the preceding phase's final verification and review
gate passes. Phase 1 may use a local image tag for integration tests; the
operator-facing Compose reference changes to `ghcr.io/mailcow/mcp:0.1.0` only
after the publishing workflow can produce that exact tag.

## Locked Source Layout

The application lives under one Docker build context:

```text
data/Dockerfiles/mcp/
  Dockerfile
  package.json
  package-lock.json
  tsconfig.json
  vitest.config.ts
  src/
    app.ts
    config.ts
    server.ts
    db/
      init.ts
      migrations.ts
      pool.ts
      migrations/
        001_initial.sql
        002_oauth.sql
        003_attachments.sql
    auth/
      account-repository.ts
      credential-verifier.ts
      crypto-vault.ts
      oidc-adapter.ts
      oidc-provider.ts
      signing-keys.ts
      interactions.ts
      token-verifier.ts
    http/
      errors.ts
      metadata.ts
      rate-limit.ts
      uploads.ts
    mcp/
      context.ts
      server.ts
      transport.ts
      tools/
        folders.ts
        messages.ts
        organize.ts
        send.ts
        attachments.ts
    mail/
      handles.ts
      imap-gateway.ts
      smtp-gateway.ts
      mime.ts
    attachments/
      repository.ts
      staging-store.ts
      upload-tokens.ts
      validation.ts
      upload-app.html
    audit/
      repository.ts
      redaction.ts
  test/
    fixtures/
    integration/
    unit/
```

Keep files focused on the responsibility shown above. Do not introduce an ORM,
framework-level dependency-injection container, frontend framework, Redis
state, or a second database.

## Cross-Phase Interface Contracts

These names and shapes are fixed so later phases can be implemented without
renaming earlier work:

```ts
export type Scope = "mail.read" | "mail.send" | "mail.organize";

export interface AccountContext {
  accountId: string;
  clientId: string;
  scopes: ReadonlySet<Scope>;
  tokenExpiresAt: number;
}

export interface StoredCredential {
  accountId: string;
  mailbox: string;
  appPassword: string;
}

export interface CredentialVault {
  seal(
    recordType: string,
    accountId: string,
    plaintext: Uint8Array,
  ): Promise<string>;
  open(
    recordType: string,
    accountId: string,
    envelope: string,
  ): Promise<Uint8Array>;
}

export interface CredentialVerifier {
  verify(mailbox: string, appPassword: string): Promise<void>;
}

export interface HandleCodec {
  encode<T>(
    kind: "folder" | "message" | "attachment" | "cursor",
    accountId: string,
    value: T,
    ttlSeconds: number,
  ): Promise<string>;
  decode<T>(
    expectedKind: "folder" | "message" | "attachment" | "cursor",
    accountId: string,
    handle: string,
  ): Promise<T>;
}

export interface FolderRef {
  path: string;
  delimiter: string;
}

export interface MessageRef {
  folder: string;
  uid: number;
  uidValidity: string;
}

export interface AttachmentRef extends MessageRef {
  part: string;
  filename: string;
  mimeType: string;
  size: number;
}

export interface FolderInfo {
  path: string;
  delimiter: string;
  subscribed: boolean;
  specialUse?: string;
  unread?: number;
}

export interface SearchQuery {
  folder: string;
  text?: string;
  sender?: string;
  recipient?: string;
  subject?: string;
  since?: Date;
  before?: Date;
  unread?: boolean;
  hasAttachments?: boolean;
  beforeUid?: number;
  limit: number;
}

export interface MessageSummary {
  ref: MessageRef;
  subject: string;
  from: string[];
  to: string[];
  date?: Date;
  flags: string[];
  summary: string;
  hasAttachments: boolean;
}

export interface MessageContent extends MessageSummary {
  text?: string;
  sanitizedHtml?: string;
  messageId?: string;
  inReplyTo?: string;
  references: string[];
  attachments: AttachmentRef[];
}

export interface ImapGateway {
  listFolders(): Promise<FolderInfo[]>;
  createFolder(path: string): Promise<"created" | "existing">;
  subscribe(path: string): Promise<void>;
  search(query: SearchQuery): Promise<MessageSummary[]>;
  getMessage(ref: MessageRef, peek: true): Promise<MessageContent | null>;
  move(refs: MessageRef[], destination: string): Promise<void>;
  openAttachment(ref: AttachmentRef): Promise<NodeJS.ReadableStream>;
}

export interface OutgoingMessage {
  envelopeFrom: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text?: string;
  html?: string;
  inReplyTo?: string;
  references: string[];
  attachments: Array<{
    filename: string;
    mimeType: string;
    content: NodeJS.ReadableStream;
  }>;
}

export interface SendResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
  outcome: "accepted" | "rejected" | "ambiguous";
}

export interface SmtpGateway {
  send(message: OutgoingMessage): Promise<SendResult>;
}

export interface MailSessionFactory {
  withImap<T>(
    account: StoredCredential,
    operation: (imap: ImapGateway) => Promise<T>,
  ): Promise<T>;
  withSmtp<T>(
    account: StoredCredential,
    operation: (smtp: SmtpGateway) => Promise<T>,
  ): Promise<T>;
}

export interface UploadMetadata {
  filename: string;
  declaredMimeType: string;
  detectedMimeType: string;
  size: number;
  sha256: string;
  expiresAt: Date;
}

export interface StagedAttachment {
  id: string;
  accountId: string;
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  expiresAt: Date;
  state: "ready" | "sending";
}

export interface AttachmentStore {
  stage(
    accountId: string,
    source: NodeJS.ReadableStream,
    metadata: UploadMetadata,
  ): Promise<StagedAttachment>;
  open(accountId: string, attachmentId: string): Promise<NodeJS.ReadableStream>;
  consume(accountId: string, attachmentId: string): Promise<void>;
}
```

Every MCP handler obtains `AccountContext` from
`extra.authInfo.extra.accountId`; absence or type mismatch is an authentication
failure. A handler checks its required scope before decoding any handle or
opening an upstream protocol connection.

## Dependency Pins

Create `package-lock.json` with `npm install --save-exact`; the direct pins are:

```json
{
  "@modelcontextprotocol/ext-apps": "1.7.5",
  "@modelcontextprotocol/sdk": "1.29.0",
  "busboy": "1.6.0",
  "cookie-parser": "1.4.7",
  "express": "5.2.1",
  "express-rate-limit": "8.6.0",
  "file-type": "22.0.1",
  "helmet": "8.3.0",
  "imapflow": "1.5.0",
  "mailparser": "3.9.14",
  "mysql2": "3.23.1",
  "nodemailer": "9.0.3",
  "oidc-provider": "9.10.0",
  "pino": "10.3.1",
  "pino-http": "11.0.0",
  "sanitize-html": "2.17.6",
  "yauzl": "3.4.0",
  "zod": "4.4.3"
}
```

Development pins are `typescript@7.0.2`, `vitest@4.1.10`,
`tsx@4.23.1`, `@types/node@26.1.1`, `@types/express@5.0.6`,
`@types/oidc-provider@9.5.0`, and the matching current `@types` packages listed
in each phase. Use Node `24.18.0-alpine3.24` for build and runtime stages.

## Configuration Surface

Generation and migration must write these exact public options and defaults:

```env
COMPOSE_PROFILES=
MCP_CONFIG_VERSION=1
MCP_UPDATE_OFFERED=1
MCP_DBNAME=mailcow_mcp
MCP_DBUSER=mailcow_mcp
MCP_DBPASS=<automatically-generated-64-character-hex-secret>
MCP_ENCRYPTION_KEY=<automatically-generated-64-character-hex-key>
MCP_OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback
MCP_ATTACHMENT_MAX_BYTES=10485760
MCP_MESSAGE_MAX_BYTES=26214400
MCP_BASE64_UPLOAD_MAX_BYTES=1048576
MCP_UPLOAD_TTL_SECONDS=3600
MCP_ATTACHMENT_ALLOWED_TYPES=pdf,xlsx,csv,txt,png,jpg,jpeg
MCP_LOGIN_ATTEMPTS=5
MCP_LOGIN_WINDOW_SECONDS=900
MCP_REGISTRATIONS_PER_HOUR=10
MCP_REQUESTS_PER_MINUTE=120
MCP_SENDS_PER_MINUTE=10
MCP_RECIPIENTS_PER_HOUR=100
MCP_CONCURRENT_UPLOADS=5
MCP_AUDIT_RETENTION_DAYS=30
```

Compose supplies internal-only `MCP_DBHOST=mysql-mailcow`,
`MCP_IMAP_HOST=dovecot-mailcow`, `MCP_SMTP_HOST=postfix-mailcow`, and
`MCP_PORT=3000`; these are not administrator-facing mailcow options.

## Shared Verification

Run this at every phase gate:

```bash
docker run --rm \
  -v "$PWD/data/Dockerfiles/mcp:/app" \
  -w /app node:24.18.0-alpine3.24 \
  sh -lc 'npm ci && npm run typecheck && npm test'
docker compose config -q
git diff --check
git status --short
```

Expected: typecheck exits zero, all Vitest suites pass, Compose validation
exits zero, the diff has no whitespace errors, and status contains only the
phase's intended files before commit.

## Primary References

- [Approved design](../specs/2026-07-26-mailcow-remote-mcp-design.md)
- [MCP authorization specification,
  2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP TypeScript SDK v1 server
  documentation](https://ts.sdk.modelcontextprotocol.io/server)
- [`oidc-provider`
  documentation](https://github.com/panva/node-oidc-provider)
- [MCP Apps stable extension](https://modelcontextprotocol.io/extensions/apps/overview)
