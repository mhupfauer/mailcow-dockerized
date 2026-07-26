# Mailcow Remote MCP Server Design

## Summary

Add a multi-user, remotely hosted Model Context Protocol (MCP) server to
mailcow-dockerized. Users connect from Claude through Streamable HTTP, sign in
with a dedicated mailcow app password, and receive access only to their own
mailbox. The server supports reading and organizing mail, creating folders,
moving messages, sending mail directly, and reading or sending attachments.

The add-on runs as a sibling Compose service. It does not modify or install code
inside an existing mailcow container. It is delivered through tracked mailcow
Compose and nginx templates under an opt-in `mcp` profile so both new and
pre-existing installations receive it safely through `update.sh`.

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
- Follow mailcow's tracked Compose, nginx template, configuration-migration,
  and MariaDB patterns so upgrades remain manageable.
- Let existing installations adopt the feature through one confirmation,
  without manually creating secrets, editing Compose YAML, editing nginx, or
  running SQL.
- Keep normal mail delivery available if MCP activation or a later MCP
  migration fails.

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
- Automatically enabling a new public mailbox-data endpoint during a routine
  mailcow update.

## User Experience

1. An administrator enables the optional service once during `update.sh` or
   later with `./helper-scripts/mcp.sh enable`.
2. A mailbox user signs in to the mailcow UI.
3. The user creates an app password named `Claude MCP` and enables only IMAP
   and SMTP.
4. The user adds `https://${MAILCOW_HOSTNAME}/mcp` as a custom connector in
   Claude.
5. Claude discovers the authorization server and starts an authorization-code
   flow with PKCE-S256.
6. The MCP login page asks for the user's full email address and the dedicated
   app password.
7. The service verifies the credentials against both IMAP and SMTP, then shows
   consent for `mail.read`, `mail.send`, and `mail.organize`.
8. After consent, Claude receives opaque access and refresh tokens. Claude
   never receives the app password.
9. MCP calls use the token subject to select the credential and mailbox.
10. Revoking the app password in mailcow causes subsequent mailbox operations
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

The service is declared in the tracked base Compose file under the optional
`mcp` profile and is attached to `mailcow-network`. Its Node.js port is not
published to the host. Mailcow nginx terminates TLS and proxies only the
documented routes. The tracked nginx template renders those routes only when
the exact `mcp` profile token is enabled.

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

- Authorization Code for interactive authorization plus the Refresh Token
  grant for session continuation; no other grant types.
- Mandatory PKCE-S256 for public clients.
- Opaque access tokens with a 15-minute lifetime.
- Rotating opaque refresh tokens with a 30-day maximum lifetime.
- Authorization codes with a two-minute lifetime and one-time consumption.
- Resource indicators and an audience fixed to
  `https://${MAILCOW_HOSTNAME}/mcp`.
- Scopes `mail.read`, `mail.send`, and `mail.organize`. An authorization
  request that omits the `scope` parameter is treated as requesting all three
  scopes, because many MCP clients send no scope parameter.
- Persistent consent until the user disconnects the connector, revokes the
  grant, or revokes the app password.

Dynamic registration is enabled for Claude's zero-configuration connection
flow but is constrained as follows:

- Redirect URIs must exactly match an entry in
  `MCP_OAUTH_ALLOWED_REDIRECT_URIS`, or, when
  `MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=1` (the default), be an RFC 8252
  loopback redirect: an `http` URI whose host is `127.0.0.1`, `[::1]`, or
  `localhost`, with any port. This admits CLI clients such as Claude Code.
  Non-loopback `http` redirect URIs are always rejected.
- The default allowed redirect URIs are
  `https://claude.ai/api/mcp/auth_callback` and
  `https://claude.com/api/mcp/auth_callback`.
- Only `authorization_code` and `refresh_token`, response type `code`, and
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

A considered alternative was verifying submitted credentials directly against
mailcow's `app_passwd` table, which would reject primary passwords by design
and keep failed guesses away from Dovecot entirely. It was rejected for
version one because it would grant the MCP service read access to mailcow's
core authentication data and cross the deliberate database boundary that
limits the service to its own `mailcow_mcp` schema.

Failed logins are rate-limited by source IP and normalized mailbox before
reaching Dovecot. Limits prevent credential stuffing and prevent repeated
attempts from causing mailcow to ban the shared MCP container address. The
rate limiter runs before any IMAP or SMTP connection is opened, and tests
assert that no protocol attempt occurs once a source or mailbox is limited,
keeping the MCP container below netfilter's ban thresholds.

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

A scheduled cleanup deletes expired `oidc-provider` rows and removes
dynamically registered clients that hold no surviving grant thirty days after
their last token activity, so abandoned registrations and expired OAuth
artifacts do not accumulate indefinitely.

The existing physical MariaDB volume backup includes this database. Temporary
attachment files are intentionally excluded from durable backups.

## Encryption and Secret Configuration

The master encryption key is configured through mailcow's existing
`mailcow.conf` environment mechanism:

```env
MCP_ENCRYPTION_KEY=<64 lowercase or uppercase hexadecimal characters>
```

New installations and the first MCP-aware update generate this value
automatically with a cryptographically secure random source. The equivalent
manual recovery command is:

```bash
openssl rand -hex 32
```

When MCP is enabled, startup and update preflight fail if the key is absent or
does not decode to exactly 32 bytes. A disabled installation reports the
problem but may continue a core-only mailcow update. Once
`MCP_CONFIG_VERSION` exists, update code never silently regenerates a missing
or invalid key because doing so would make existing encrypted data unreadable.
It instructs the operator to restore the `mailcow.conf` backup or use an
explicit future credential-reset procedure. The key is never stored in MariaDB
or logs. Mailcow already restricts `mailcow.conf` to mode `0600`; all automated
edits preserve that permission.

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

After a definitive SMTP acceptance, the service appends the composed message
to the account's special-use Sent folder with the Seen flag, so mail sent
through MCP appears in the user's normal mail history. A failed append does
not fail the tool call: the response still reports the send as successful and
sets `sent_copy_saved` to false so the client can surface the missing Sent
copy. No append is attempted after an ambiguous SMTP outcome.

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

Combining mail reading with mail sending creates a prompt-injection
exfiltration surface: a hostile inbound message can instruct a model to
forward private data. Version one accepts this risk deliberately and
documents it. The MCP client's interactive confirmation of write tools such
as `send_email` is the operative control, and the administrator documentation
states this explicitly rather than implying the server can prevent it.

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
COMPOSE_PROFILES=
MCP_CONFIG_VERSION=1
MCP_UPDATE_OFFERED=1
MCP_DBNAME=mailcow_mcp
MCP_DBUSER=mailcow_mcp
MCP_DBPASS=<automatically-generated-64-character-hex-secret>
MCP_ENCRYPTION_KEY=<automatically-generated-64-character-hex-key>
MCP_OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback
MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=1
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

`COMPOSE_PROFILES` is the source of truth for enablement. The feature is active
only when the value contains `mcp` as an exact comma-separated token. The
helper appends or removes only that token and preserves any unrelated profiles.
Mailcow scripts unset an inherited shell-level `COMPOSE_PROFILES` before
invoking Compose so it cannot override the value in `.env`/`mailcow.conf`.

`MCP_CONFIG_VERSION=1` distinguishes a configuration that has already received
MCP secrets from an older installation. On a new installation,
`generate_config.sh` writes all MCP defaults and cryptographically secure
secrets but leaves `mcp` out of `COMPOSE_PROFILES`. On the first MCP-aware
update of an existing installation, `adapt_new_options` generates a 32-byte
hexadecimal `MCP_DBPASS`, generates the 32-byte hexadecimal
`MCP_ENCRYPTION_KEY`, and writes the version marker last. It builds the new
configuration in a temporary file and atomically replaces `mailcow.conf`, so a
partial write cannot leave the marker without its secrets. Neither secret is
printed. Re-running the migration is idempotent and preserves existing values.

`MCP_UPDATE_OFFERED` records the one-time adoption decision independently of
the configuration version. New installations write it as `1`. A pre-existing
installation initially receives `0`; the first successful MCP-aware update
sets it to `1` after asking the interactive question, or after printing the
manual opt-in command in unattended or `--skip-start` mode.

An empty or invalid database password or encryption key is an MCP enablement
and startup error. It aborts an enabled installation's update preflight before
core services are stopped; on a disabled installation it is reported without
blocking the core update. After the version marker exists, automation must not
replace either credential. Installation documentation includes secure
commands only for explicit recovery or reset procedures.

## Existing Installations, Update, and Activation

The feature is shipped to old and new installations through tracked repository
files. It does not depend on `docker-compose.override.yml`,
`data/conf/nginx/*.custom`, or another ignored local file, because `update.sh`
cannot reliably add or maintain those files.

The repository changes are explicit:

- `generate_config.sh` defines defaults and first-install secrets.
- `_modules/scripts/new_options.sh` migrates existing configurations.
- `docker-compose.yml` declares the profiled services and volume.
- `data/Dockerfiles/nginx/bootstrap.py` parses the exact profile token for the
  template context.
- `data/conf/nginx/templates/sites-default.conf.j2` contains the conditional
  routes.
- `helper-scripts/mcp.sh` owns enable, disable, status, retry, and purge.
- `update.sh` adds preflight, post-merge validation, the one-time offer, and
  MCP-specific result reporting.

### First MCP-aware update

The normal configuration migration runs before activation:

1. Mailcow's existing `_modules` self-refresh/restart behavior loads the new
   migration code; rerunning `update.sh` after that standard restart requires
   no MCP-specific preparation.
2. The refreshed update module detects the missing `MCP_CONFIG_VERSION` before
   the first Compose validation or container shutdown.
3. It backs up `mailcow.conf`, atomically adds the two MCP secrets without
   displaying them, appends the MCP defaults, sets `MCP_UPDATE_OFFERED=0`, and
   writes the configuration marker last while preserving mode `0600`.
4. The update merges the tracked Compose services, database initializer,
   helper script, and conditional nginx template.
5. Core mailcow services are updated and started independently of MCP.
6. After the core stack starts, an interactive update with
   `MCP_UPDATE_OFFERED=0` asks once whether to enable the MCP service now. The
   default answer is no.
7. A yes answer invokes `./helper-scripts/mcp.sh enable`; a no answer leaves a
   ready but disabled configuration and prints that command for later use.
   Either answer atomically records `MCP_UPDATE_OFFERED=1`.

`update.sh --force` and other non-interactive execution never enable a
previously disabled installation and never expose the new routes. They
generate the required configuration values, leave `COMPOSE_PROFILES`
unchanged, record that the offer was handled, and print the opt-in command in
the update summary. `--skip-start` behaves the same way because activation
cannot be verified while the core stack is intentionally stopped.

### Transactional enable

`./helper-scripts/mcp.sh enable` performs one administrator-facing operation:

1. Verify privileges, acquire a dedicated lock, and create a mode-`0600`
   backup of `mailcow.conf`.
2. Generate secrets only for a genuinely pre-marker configuration. If the
   marker already exists and a secret is missing or invalid, stop and direct
   the administrator to recovery instead of replacing it.
3. Atomically add the exact `mcp` token to `COMPOSE_PROFILES`, preserve other
   profile tokens, and record `MCP_UPDATE_OFFERED=1`.
4. Run `docker compose --profile mcp config -q`.
5. Pull the pinned prebuilt MCP image from the mailcow GHCR namespace.
6. Ensure MariaDB is available, run the idempotent database initializer, and
   run schema migrations with the restricted MCP database user.
7. Start the MCP application and recreate or reload nginx so the conditional
   public routes become active.
8. Verify OAuth discovery and verify that an unauthenticated `/mcp` request
   returns the expected `401` response and protected-resource metadata.

If any step fails, the helper stops and removes the MCP application, restores
the previous configuration/profile state, and recreates nginx without the MCP
routes. Database objects created before failure may remain for diagnosis and a
later retry, but no core mail service depends on them. Activation failure
therefore cannot take SMTP, IMAP, or the normal mailcow UI offline.

### Later updates

An update treats an exact `mcp` token in `COMPOSE_PROFILES` as an already
enabled installation. Before stopping services it validates the configuration
marker, database password, encryption-key format, and profile syntax. After
the repository merge it runs `docker compose config -q` again so newly shipped
Compose content is validated, not merely the pre-update file.

The normal image pull and `compose up` include the active profile, run
idempotent initialization and schema migration, and health-check the MCP
service. Existing secrets, database contents, OAuth grants, and enabled state
are preserved. MCP services remain dependency leaves: a failed MCP pull,
migration, or health check is reported prominently, but core mail services are
still brought up. The update summary gives a focused recovery or retry command.

### Disable and purge

`./helper-scripts/mcp.sh disable` atomically removes only the `mcp` profile
token, stops MCP-profile services, and recreates nginx without public MCP
routes. It preserves the MCP database, database credentials, encryption key,
OAuth state, and temporary attachment volume so re-enabling is reversible.

Permanent cleanup is a distinct `./helper-scripts/mcp.sh purge` operation with
an explicit destructive confirmation. Purge removes the dedicated database
and temporary volume only after the service is disabled; it is never called by
`update.sh` or ordinary disable. Existing mailbox data is outside its scope.

## Compose and Nginx Integration

- The tracked base `docker-compose.yml` declares the one-shot database
  initializer and `mcp-mailcow` service under the optional `mcp` profile.
- The application uses a version-pinned, prebuilt image from the mailcow GHCR
  namespace. Operators do not need Node.js or a local image build.
- Only nginx can reach the application HTTP port through `mailcow-network`.
- The MCP service can reach `mysql-mailcow`, `dovecot-mailcow`, and
  `postfix-mailcow`.
- The tracked nginx templates conditionally proxy only the documented routes
  when the exact `mcp` profile token is active, and set explicit request-body,
  streaming, and timeout limits.
- Nginx receives the profile value as template input; disabled installations
  render no MCP location blocks and expose no discovery, OAuth, login, upload,
  or MCP endpoint.
- Enabled templates use Docker DNS resolution at request time rather than a
  startup-resolved static upstream. An absent or unhealthy MCP container can
  therefore produce an MCP-route `502` but cannot prevent nginx from serving
  the mailcow UI and other routes.
- The Streamable HTTP route disables proxy buffering where streaming requires
  it.
- The upload route has a request-body limit consistent with
  `MCP_MESSAGE_MAX_BYTES`; application streaming enforces both per-file and
  aggregate limits.
- Container health checks use an internal liveness/readiness route that
  exposes no credentials or configuration.
- Schema migration and database readiness precede application readiness.
- The database initializer alone receives `DBROOT`; the long-running service
  receives only its dedicated database credentials.
- No core mailcow service depends on an MCP-profile service.
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
- Sent-folder append after definitive acceptance, success-with-warning on
  append failure, and no append after rejection or an ambiguous outcome.
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

### Installation and update tests

- Migrate a representative pre-MCP `mailcow.conf`, generating both secrets and
  the marker without changing existing options or file mode.
- Re-run configuration migration and prove the generated secrets and enabled
  state remain byte-for-byte unchanged.
- Fail closed when a marked configuration has a missing or malformed key or
  database password.
- Enable and disable repeatedly while preserving unrelated
  `COMPOSE_PROFILES` tokens.
- Verify interactive yes/no behavior and prove `update.sh --force` never
  enables MCP on a previously disabled installation.
- Verify the one-time offer marker for new installs, interactive yes/no,
  `--force`, interrupted updates, and `--skip-start`.
- Inject failures at Compose validation, image pull, database initialization,
  schema migration, application startup, nginx activation, and health
  verification; each must roll back routes/profile state and leave core mail
  services available.
- Update an already enabled installation and verify its database, key, grants,
  profile, and endpoint survive.
- Verify disable preserves state and purge requires a separate confirmation.
- Validate both the pre-merge and post-merge Compose configurations.

## Rollout

Version one ships disabled to both new and pre-existing installations. Presence
of generated configuration does not expose an endpoint; only the active `mcp`
profile does. Interactive updates offer the transactional enable helper once,
while forced or unattended updates remain opt-in.

The existing physical MariaDB-volume backup includes the dedicated MCP
database. Operators must also back up `mailcow.conf`, because encrypted MCP
records cannot be recovered without `MCP_ENCRYPTION_KEY`. Temporary staged
attachments are deliberately ephemeral and excluded from durable backup
expectations.

Rollback uses the disable helper and does not modify mailbox data. The
dedicated database, credentials, encryption key, OAuth state, and temporary
volume remain available for recovery or re-enable. Destructive cleanup is
reserved for the separately confirmed purge operation.
