# Mailcow Remote MCP Server Design

## Summary

Add a multi-user, remotely hosted Model Context Protocol (MCP) server to
mailcow-dockerized. Users connect from Claude through Streamable HTTP, sign in
with a dedicated mailcow app password, and receive access only to their own
mailbox. The server supports reading and organizing mail, creating folders,
moving messages, sending mail directly, and reading or sending attachments.

The add-on runs as a sibling Compose service. It does not modify or install code
inside an existing mailcow container.

## Goals

- Provide a public Streamable HTTP endpoint at
  `https://${MAILCOW_HOSTNAME}/mcp`.
- Require per-user OAuth authorization for the remote MCP endpoint without
  introducing an external identity provider.
- Use a dedicated mailcow app password, restricted to IMAP and SMTP, instead of
  the user's primary password.
- Enforce mailbox isolation from the authenticated OAuth identity rather than
  from model-supplied mailbox parameters.
- Support IMAP folder listing, message search and reading, folder creation, and
  message moves, including reversible moves to Trash and Junk.
- Support direct SMTP sending, including text, HTML, replies, CC/BCC, and
  attachments.
- Support PDF, Excel, and other approved attachment types without routing large
  base64 payloads through model context.
- Follow mailcow's Compose override, nginx custom include, configuration, and
  MariaDB patterns so upgrades remain manageable.

## Non-goals

- Permanent message deletion or IMAP expunge.
- Administrator or cross-mailbox access.
- Mailcow domain, alias, mailbox, or quarantine administration.
- Calendar, contacts, POP3, Sieve, or ActiveSync access.
- OAuth federation with Keycloak or another external identity provider.
- A local npm package or Claude Desktop extension.
- Automatic access to arbitrary paths on a user's computer.
- Parsing or executing attachment contents inside the MCP service.
- Encryption-key rotation in version one.

## User Experience

1. A mailbox user signs in to the mailcow UI.
2. The user creates an app password named `Claude MCP` and enables only IMAP
   and SMTP.
3. The user adds `https://${MAILCOW_HOSTNAME}/mcp` as a custom connector in
   Claude.
4. Claude discovers the authorization server and starts an authorization-code
   flow with PKCE-S256.
5. The MCP login page asks for the user's full email address and the dedicated
   app password.
6. The service verifies the credentials against both IMAP and SMTP, then shows
   consent for `mail.read`, `mail.send`, and `mail.organize`.
7. After consent, Claude receives opaque access and refresh tokens. Claude
   never receives the app password.
8. MCP calls use the token subject to select the credential and mailbox.
9. Revoking the app password in mailcow causes subsequent mailbox operations
   to require reauthentication.

## Architecture

```text
Claude / Anthropic MCP proxy
             |
             | HTTPS, OAuth bearer token, Streamable HTTP
             v
mailcow nginx on https://${MAILCOW_HOSTNAME}
  |-- /mcp
  |-- /oauth/*
  |-- /mcp-login/*
  |-- /mcp-upload/*
  `-- /.well-known/*
             |
             v
       mcp-mailcow
  |-- MCP resource server
  |-- oidc-provider authorization server
  |-- login and consent application
  |-- MariaDB persistence adapter
  |-- encrypted credential vault
  |-- IMAP adapter
  |-- SMTP/MIME adapter
  `-- attachment staging service
       |          |             |
       |          |             `-- encrypted temporary attachment volume
       |          `-- mysql-mailcow, dedicated database and user
       `-- dovecot-mailcow / postfix-mailcow
```

The service is attached to `mailcow-network`. Its Node.js port is not published
to the host. Mailcow nginx terminates TLS and proxies only the documented
routes.

## Public Routes

- `/mcp`: Streamable HTTP MCP endpoint.
- `/.well-known/oauth-protected-resource/mcp`: RFC 9728 protected-resource
  metadata for the MCP resource.
- `/.well-known/oauth-authorization-server`: RFC 8414 authorization-server
  metadata.
- `/.well-known/openid-configuration`: OIDC discovery metadata required by
  `oidc-provider` and compatible clients.
- `/oauth/auth`: authorization endpoint.
- `/oauth/token`: token endpoint.
- `/oauth/reg`: restricted dynamic client registration endpoint.
- `/oauth/revocation`: token revocation endpoint.
- `/oauth/jwks`: public signing keys.
- `/mcp-login/:interaction`: login and consent UI.
- `/mcp-upload/:token`: one-time attachment upload page and multipart POST
  endpoint.

Nginx forwards the original host, scheme, and client IP. The application trusts
forwarded headers only from the nginx container/network path.

## OAuth Design

`oidc-provider` is embedded as a module but separated from mailbox and MCP
logic behind internal interfaces. This keeps a future migration to Ory Hydra
limited to the authorization boundary.

Version one uses:

- Authorization Code grant only.
- Mandatory PKCE-S256 for public clients.
- Opaque access tokens with a 15-minute lifetime.
- Rotating opaque refresh tokens with a 30-day maximum lifetime.
- Authorization codes with a two-minute lifetime and one-time consumption.
- Resource indicators and an audience fixed to
  `https://${MAILCOW_HOSTNAME}/mcp`.
- Scopes `mail.read`, `mail.send`, and `mail.organize`.
- Persistent consent until the user disconnects the connector, revokes the
  grant, or revokes the app password.

Dynamic registration is enabled for Claude's zero-configuration connection
flow but is constrained as follows:

- Redirect URIs must exactly match an entry in
  `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
- The default allowed redirect URI is
  `https://claude.ai/api/mcp/auth_callback`.
- Only `authorization_code`, response type `code`, and
  `token_endpoint_auth_method=none` are accepted.
- PKCE-S256 is mandatory.
- Registration is rate-limited and audited.

The MCP endpoint validates token activity, audience, subject, and scopes on
every HTTP request. An MCP session identifier, when used by the pinned stable
SDK/protocol version, is never treated as authentication.

## Login and Consent

The login form accepts only:

- A syntactically valid full mailbox email address.
- A mailcow app password.

The service performs IMAP and SMTP authentication over STARTTLS. Both must
succeed because version one includes read and send capabilities. A normal
mailbox password may also technically authenticate at the protocol layer, so
the UI explicitly instructs users to provide a dedicated app password. The
service cannot distinguish a normal password from an app password through
IMAP/SMTP alone.

Failed logins are rate-limited by source IP and normalized mailbox before
reaching Dovecot. Limits prevent credential stuffing and prevent repeated
attempts from causing mailcow to ban the shared MCP container address.

On success, the service creates an internal random account identifier. OAuth
tokens use that identifier as the subject rather than exposing the mailbox
address.

Consent grants are restricted to the three documented scopes. The login and
consent pages use CSRF tokens, strict redirect validation, a restrictive
Content Security Policy, and secure path-scoped cookies with unique names,
`HttpOnly`, `Secure`, and `SameSite=Lax`.

## MariaDB Persistence

The add-on reuses `mysql-mailcow` but has a separate database and
least-privilege user:

```env
MCP_DBNAME=mailcow_mcp
MCP_DBUSER=mailcow_mcp
MCP_DBPASS=<generated-password>
```

An idempotent one-shot initialization service receives `DBROOT`, validates the
configured identifiers, creates the database and user if needed, and grants
access only to `${MCP_DBNAME}.*`. The running `mcp-mailcow` service never
receives `DBROOT`, mailcow's `DBUSER`, or mailcow's `DBPASS`.

The MCP service runs versioned schema migrations with its restricted database
user before accepting traffic. A failed migration fails readiness and prevents
the service from serving requests.

The `oidc-provider` adapter is implemented directly against MariaDB according
to its documented persistence interface. It supports model-specific upsert,
lookup, expiry, consumption, grant revocation, user-code lookup, and UID
lookup. Expiry and lookup columns are indexed. Adapter contract tests cover
every model used by the enabled OAuth features.

The database also holds:

- Internal accounts and mailbox metadata.
- Consent and OAuth grant metadata.
- Encrypted app-password records.
- Attachment metadata and ownership.
- Audit events.
- Encrypted authorization-server signing-key material.

Opaque token identifiers and upload tokens are stored as one-way hashes. Raw
bearer tokens and upload tokens exist only in the value returned to the client.

The existing physical MariaDB volume backup includes this database. Temporary
attachment files are intentionally excluded from durable backups.

## Encryption and Secret Configuration

The master encryption key is configured through mailcow's existing
`mailcow.conf` environment mechanism:

```env
MCP_ENCRYPTION_KEY=<64 lowercase or uppercase hexadecimal characters>
```

Generate it with:

```bash
openssl rand -hex 32
```

Startup fails if the key is absent or does not decode to exactly 32 bytes. The
key is never stored in MariaDB or logs. Mailcow already restricts
`mailcow.conf` to mode `0600`; operators must preserve that permission.

App passwords, staged attachment bytes, and private signing-key material are
encrypted with AES-256-GCM. Every encrypted object uses a fresh random 96-bit
nonce and authenticates its record type and account identifier as additional
authenticated data. The database stores the nonce, authentication tag,
ciphertext, and encryption format version.

Changing `MCP_ENCRYPTION_KEY` without a future rotation procedure makes
existing encrypted records unusable. Version one detects decryption failures,
fails closed, and requires users to reconnect rather than silently replacing
credentials.

## Mail Protocol Connections

The service connects to:

- `dovecot-mailcow:143` using STARTTLS for IMAP.
- `postfix-mailcow:587` using STARTTLS for SMTP submission.

TLS certificate verification remains enabled. The TLS server name is
`${MAILCOW_HOSTNAME}` even though Docker service names are used for routing.
Authentication uses the full mailbox email address and app password with PLAIN
authentication only inside the verified TLS tunnel.

IMAP and SMTP connections or pools are isolated by internal account ID.
Credentials, connections, message handles, and attachment handles are never
shared across accounts.

## MCP Tools and Resources

### `list_folders`

Returns subscribed and available IMAP folders, special-use flags, hierarchy,
and opaque folder handles. It also returns unread counts when Dovecot
advertises `LIST-STATUS`; otherwise counts are omitted rather than issuing an
additional status request for every folder.

### `search_messages`

Accepts optional folder, free-text query, sender, recipient, subject, date
range, unread state, and attachment presence. Results are cursor-paginated and
contain bounded summaries, headers, flags, and opaque message handles. The
default limit is 20 and the maximum is 50.

### `get_message`

Accepts an opaque message handle and uses IMAP peek semantics so reading through
MCP does not change the Seen flag. Returns normalized headers, text body,
sanitized HTML when requested, threading headers, flags, and attachment
metadata. Remote images and other external resources are never fetched.

### `create_folder`

Creates a top-level or nested folder using Dovecot's advertised hierarchy
delimiter. Folder names are normalized and validated. New folders are
subscribed automatically. Repeating the same request for an existing folder is
an idempotent success.

### `move_messages`

Moves one or more message handles to an existing destination folder using IMAP
`UID MOVE`. Handles bind the account, folder, UID, and UIDVALIDITY so stale
handles cannot select a different message. Trash and Junk are valid
destinations. The service does not expunge messages or expose permanent
deletion.

### `create_attachment_upload`

Creates an account-bound, single-purpose upload token with a one-hour expiry.
The tool returns:

- An MCP App resource that can render an inline file picker.
- A normal browser URL as a fallback.
- A documented multipart POST URL for custom harnesses.

When the host supports MCP Apps, the upload token is delivered in client-only
tool metadata rather than model-visible text. The standalone page exchanges
the path token for a short-lived, secure upload cookie and redirects to a
tokenless URL before rendering. It sets `Referrer-Policy: no-referrer`, loads
no third-party resources, and never records the token in access logs. A direct
programmatic multipart POST consumes the path token on its first accepted
request.

### `upload_attachment_base64`

Accepts a filename, MIME type, and base64 data for small generated files. The
decoded payload is limited by `MCP_BASE64_UPLOAD_MAX_BYTES`, which defaults to
1 MiB. This tool is not the normal path for PDFs or spreadsheets.

### `send_email`

Sends immediately in one tool call. Inputs include:

- Required `to`, `subject`, and at least one of `body_text` or `body_html`.
- Optional `cc`, `bcc`, reply-to message handle, and attachment identifiers.

The authenticated mailbox fixes both the SMTP envelope sender and the visible
From address. Version one does not send as aliases. Header values reject CR/LF
characters. The tool returns the SMTP message ID plus explicit accepted and
rejected recipient lists. Partial recipient rejection is not reported as
complete success.

`send_email`, `create_folder`, and `move_messages` are annotated as write
operations.

### Attachment resource

`get_message` returns account-bound opaque URIs such as
`mailcow-attachment://<random-id>`. `resources/read` resolves the URI only for
the authenticated account and returns text or base64-encoded
`BlobResourceContents` on demand. Attachment bytes are not included in message
search or message-body responses.

## Attachment Upload and SMTP MIME Handling

Real local files use `multipart/form-data`, not model-generated base64:

```text
local PDF/XLSX
  -> one-time authenticated upload page/API
  -> streamed validation and encryption
  -> temporary attachment ID
  -> send_email
  -> MIME multipart generation
  -> SMTP submission
```

The inline MCP App posts bytes directly to the server using its one-time token.
If host capabilities or browser policy prevent the inline flow, the same token
opens a standalone upload form. A custom harness may call the multipart POST
endpoint directly.

Staged binary data is encrypted and stored in a dedicated Docker volume, not
MariaDB. MariaDB stores account ownership, normalized filename, detected and
declared MIME types, raw size, SHA-256 digest, expiry, state, and encrypted-file
reference.

Defaults are configurable through `mailcow.conf`:

```env
MCP_ATTACHMENT_MAX_BYTES=10485760
MCP_MESSAGE_MAX_BYTES=26214400
MCP_BASE64_UPLOAD_MAX_BYTES=1048576
MCP_UPLOAD_TTL_SECONDS=3600
MCP_ATTACHMENT_ALLOWED_TYPES=pdf,xlsx,csv,txt,png,jpg,jpeg
```

The initial allowed types include PDF, OOXML Excel workbooks (`.xlsx`), CSV,
plain text, PNG, and JPEG. Legacy Excel (`.xls`), macro-enabled Office files,
executables, scripts, device files, and malformed OOXML containers are
rejected. Declared MIME type, extension, and magic-byte detection must agree
with an approved type.

Unused uploads expire after one hour. Files used in a successful send are
deleted immediately. Files from failed sends remain available only until their
original expiry so the user can retry.

The SMTP library constructs standards-compliant `multipart/alternative` and
`multipart/mixed` messages and performs base64 content-transfer encoding.
Before submission, the service estimates and then enforces the complete
encoded-message limit so base64 expansion cannot bypass
`MCP_MESSAGE_MAX_BYTES`.

Existing mailbox attachments can be forwarded by attachment identifier without
being uploaded from the client again.

## Validation and Isolation

- No MCP tool accepts a mailbox address to select the target account.
- All folder, message, attachment, and upload handles are random and
  account-bound.
- Tool input schemas reject unknown fields and enforce bounded arrays and
  strings.
- Recipient addresses are parsed and normalized by a mail-address parser.
- Header values reject newline characters.
- HTML email is sanitized for returned content; no remote resource is fetched.
- The service does not accept arbitrary remote attachment URLs, preventing an
  SSRF surface.
- Filenames are treated as labels, never filesystem paths.
- Uploads stream to bounded storage and are not fully buffered in process
  memory.
- The service never opens, renders, executes, or expands general archive
  attachments.

Email bodies and attachments are untrusted content. Tool descriptions and
results explicitly identify them as untrusted user data, not instructions for
the model.

## Rate Limits

Defaults are configurable and enforced per account and source where relevant:

- Login attempts: five per 15 minutes per IP and mailbox combination.
- OAuth client registration: ten per hour per source IP.
- MCP calls: 120 per minute per account.
- Sends: ten messages per minute and 100 recipients per hour per account.
- Concurrent uploads: five per account.

Mailcow/Postfix rate limits remain authoritative and may be stricter.

## Error Model

Tool errors use stable machine-readable codes plus concise user-facing
messages:

- `reauthentication_required`: app password was revoked or stopped working.
- `upstream_unavailable`: temporary IMAP or SMTP failure; retryable.
- `message_handle_expired`: UIDVALIDITY changed or the message no longer
  exists.
- `folder_not_found`: destination folder does not exist.
- `invalid_input`: schema, address, header, or folder-name validation failed.
- `attachment_rejected`: type, size, integrity, ownership, or expiry failure.
- `message_too_large`: predicted or actual encoded message exceeds the limit.
- `recipient_rejected`: SMTP rejected one or more recipients; includes
  accepted and rejected lists without exposing credentials.
- `rate_limited`: includes a retry-after duration.
- `internal_error`: unexpected failure with a correlation identifier.

An existing folder is an idempotent success. No automatic retry is performed
for SMTP after the server may have accepted message data, preventing duplicate
mail. Ambiguous SMTP outcomes are reported explicitly with the correlation ID.

## Logging and Audit

Operational logs contain correlation IDs, timing, upstream category, and
sanitized errors. Audit records contain internal account ID, tool or OAuth
action, outcome, message/attachment opaque IDs, recipient counts, and
timestamps. A scheduled cleanup removes audit records after
`MCP_AUDIT_RETENTION_DAYS`, which defaults to 30 days.

The following are never logged:

- App passwords or encryption keys.
- Access tokens, refresh tokens, authorization codes, upload tokens, or
  cookies.
- Email bodies or subjects.
- Attachment contents.
- Full recipient lists.
- Raw IMAP or SMTP authentication exchanges.

## Configuration

The implementation adds these options to mailcow's configuration generation
and update mechanism:

```env
MCP_DBNAME=mailcow_mcp
MCP_DBUSER=mailcow_mcp
MCP_DBPASS=
MCP_ENCRYPTION_KEY=
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

Empty database password or encryption key is a startup error. Installation
documentation provides cryptographically secure generation commands.

## Compose and Nginx Integration

- A root `docker-compose.override.yml` adds the one-shot database initializer
  and `mcp-mailcow` service.
- The application image is built from pinned source and a pinned Node.js base
  image.
- Only nginx can reach the application HTTP port through `mailcow-network`.
- The MCP service can reach `mysql-mailcow`, `dovecot-mailcow`, and
  `postfix-mailcow`.
- A custom nginx include proxies only the documented routes and sets explicit
  request-body, streaming, and timeout limits.
- The Streamable HTTP route disables proxy buffering where streaming requires
  it.
- The upload route has a request-body limit consistent with
  `MCP_MESSAGE_MAX_BYTES`; application streaming enforces both per-file and
  aggregate limits.
- Container health checks use an internal liveness/readiness route that
  exposes no credentials or configuration.
- Schema migration and database readiness precede application readiness.
- Dependencies and the container image are pinned and covered by the existing
  update workflow rather than using `latest`.

## Verification

### Unit tests

- AES-256-GCM encryption/decryption, nonce uniqueness, authenticated-data
  binding, malformed ciphertext, and wrong-key failures.
- Input validation for addresses, headers, folders, cursors, and handles.
- MIME type, OOXML classification, size accounting, filename normalization,
  and base64 decoding.
- SMTP encoded-size estimation.
- Stable error mapping and log redaction.

### Database and OAuth integration tests

- Every `oidc-provider` adapter operation and enabled model.
- Persistence across process restart.
- Expiry, one-time authorization-code consumption, grant revocation, and
  refresh-token rotation.
- Discovery and protected-resource metadata.
- Redirect allowlist and dynamic-registration restrictions.
- PKCE-S256 enforcement.
- Audience and scope enforcement on every MCP request.
- CSRF, cookie, and consent behavior.
- Idempotent database initialization and migrations.

### Mail integration tests

- Valid and invalid app-password authentication for both IMAP and SMTP.
- Folder listing, nested creation, repeated creation, and subscription.
- Search pagination and bounded message retrieval.
- UIDVALIDITY mismatch and cross-account handle rejection.
- Single and batch moves, including Trash and Junk.
- Direct sends with text, HTML, replies, CC/BCC, and partial recipient
  rejection.
- No retry after an ambiguous SMTP data-stage outcome.

### Attachment integration tests

- Standalone and inline multipart upload paths.
- Programmatic multipart POST and small base64 tool upload.
- PDF and XLSX round trips with matching SHA-256 digest.
- Existing-message attachment forwarding.
- MIME mismatch, executable, malformed OOXML, oversize, expired token, and
  cross-account rejection.
- Successful-send deletion, failed-send retention, and expiry cleanup.

### Protocol and end-to-end tests

- Streamable HTTP initialization, tool listing, tool calls, resources, errors,
  and connection cleanup using an official MCP client or Inspector.
- Nginx proxy behavior for OAuth metadata, normal POST responses, streaming,
  and uploads.
- Manual Claude custom-connector registration, login, consent, refresh,
  mailbox operations, attachment upload, and disconnect/revocation.

## Rollout

Version one is enabled only when all required MCP configuration values exist.
The normal mailcow stack remains functional when the override is absent or the
MCP service is stopped. Rollback consists of removing or disabling the
override and nginx include; it does not change mailcow mailbox data. The
dedicated MCP database and encrypted temporary attachment volume can be
retained for recovery or removed separately after an operator backup.
