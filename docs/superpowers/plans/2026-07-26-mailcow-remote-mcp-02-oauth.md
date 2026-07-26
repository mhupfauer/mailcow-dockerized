# Mailcow Remote MCP Phase 2: OAuth and Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add MariaDB-backed OAuth authorization, app-password login/consent,
encrypted account credentials, protected-resource discovery, and an
authenticated Streamable HTTP endpoint.

**Architecture:** Embed `oidc-provider` behind the same Express listener and
persist every enabled model through a dedicated MariaDB adapter. Verify the
mailbox app password against both IMAP and SMTP before creating an internal
account, encrypt the credential at rest, and place only the random account ID
in OAuth state. MCP bearer middleware resolves that ID and passes it through
`AuthInfo.extra`.

**Tech Stack:** `oidc-provider` 9.10, MCP SDK 1.29, Express 5, mysql2, Node
crypto, ImapFlow, Nodemailer, Vitest/Testcontainers.

## Global Constraints

- Apply every constraint in
  [the roadmap](2026-07-26-mailcow-remote-mcp-00-roadmap.md#global-constraints).
- Dynamic clients are public clients restricted to exact configured HTTPS
  redirect URIs, grant types `authorization_code` and `refresh_token`, response
  type `code`, and `token_endpoint_auth_method=none`.
- Registration, login, and interaction routes are rate-limited before protocol
  authentication reaches Dovecot/Postfix.
- OAuth tokens never contain mailbox addresses or app passwords.
- The app password is accepted through a secure login form and never returned
  to Claude.

---

### Task 1: Full schema and migration contract

**Files:**
- Create: `data/Dockerfiles/mcp/src/db/migrations/002_oauth.sql`
- Create: `data/Dockerfiles/mcp/test/integration/schema.test.ts`
- Create: `data/Dockerfiles/mcp/test/fixtures/expected-indexes.ts`

**Interfaces:**
- Produces tables: `oidc_objects`, `accounts`, `consents`, `audit_events`

- [ ] **Step 1: Write the failing schema assertions**

Query `INFORMATION_SCHEMA` and require:

```text
oidc_objects: model, id_hash, payload_json, grant_id, user_code_hash,
              uid_hash, consumed_at, expires_at
accounts: id, mailbox_normalized, credential_envelope, credential_version,
          created_at, updated_at, revoked_at
consents: account_id, client_id, scopes, created_at, revoked_at
audit_events: account_id, action, outcome, object_id, count_value, created_at
```

Require unique/index coverage for `(model,id_hash)`, expiry, grant ID, user-code
hash, UID hash, normalized mailbox, and audit timestamp. Assert there is no
plaintext credential or token column.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/schema.test.ts
```

Expected: FAIL because Phase 1 created only the migration bookkeeping tables.

- [ ] **Step 3: Implement idempotent schema DDL**

Use `VARBINARY(32)` for SHA-256 lookup hashes, `BINARY(16)` for random account
UUID bytes, UTC `DATETIME(6)`, foreign keys with explicit delete behavior, and
`JSON` for provider payloads. `accounts.mailbox_normalized` is unique; an
existing account is updated on successful reauthorization rather than
duplicated. Do not edit the already-applied `001_initial.sql`; migration
`002_oauth.sql` is immutable after this task.

- [ ] **Step 4: Run schema and migration replay tests**

```bash
npx vitest run test/integration/schema.test.ts \
  test/integration/db-bootstrap.test.ts
```

Expected: PASS after two migration runs.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/db data/Dockerfiles/mcp/test
git commit -m "feat: add MCP OAuth persistence schema"
```

---

### Task 2: AES-GCM vault and account repository

**Files:**
- Create: `data/Dockerfiles/mcp/src/auth/crypto-vault.ts`
- Create: `data/Dockerfiles/mcp/src/auth/account-repository.ts`
- Create: `data/Dockerfiles/mcp/test/unit/crypto-vault.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/account-repository.test.ts`

**Interfaces:**
- Produces: roadmap `CredentialVault`
- Produces:

```ts
export interface AccountRepository {
  upsertVerified(mailbox: string, appPassword: string): Promise<string>;
  getCredential(accountId: string): Promise<StoredCredential | null>;
  markCredentialRejected(accountId: string): Promise<void>;
}
```

- [ ] **Step 1: Write failing cryptographic tests**

Test round-trip, two encryptions producing different envelopes, wrong key,
wrong account ID, wrong record type, malformed base64url, modified tag, and
unknown envelope version. The envelope format is:

```text
v1.<base64url 12-byte nonce>.<base64url ciphertext+16-byte tag>
```

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/crypto-vault.test.ts
```

Expected: FAIL because the vault is absent.

- [ ] **Step 3: Implement vault and repository**

Use:

```ts
const aad = Buffer.from(`mailcow-mcp:v1:${recordType}:${accountId}`, "utf8");
const cipher = createCipheriv("aes-256-gcm", key, randomBytes(12));
cipher.setAAD(aad);
```

Normalize mailboxes by parsing a single address, lowercasing the domain, and
using the resulting full address consistently. Seal JSON
`{"mailbox":"...","appPassword":"..."}` under record type
`mailbox-credential`. Never include it in thrown errors.

- [ ] **Step 4: Run unit and MariaDB repository tests**

```bash
npx vitest run test/unit/crypto-vault.test.ts \
  test/integration/account-repository.test.ts
```

Expected: PASS, including update-in-place and rejection marking.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/auth data/Dockerfiles/mcp/test
git commit -m "feat: encrypt MCP mailbox credentials"
```

---

### Task 3: MariaDB `oidc-provider` adapter

**Files:**
- Create: `data/Dockerfiles/mcp/src/auth/oidc-adapter.ts`
- Create: `data/Dockerfiles/mcp/test/integration/oidc-adapter.test.ts`

**Interfaces:**
- Produces constructor compatible with
  `adapter: MariaDbOidcAdapter.factory(pool)`
- Implements: `upsert`, `find`, `findByUserCode`, `findByUid`, `consume`,
  `destroy`, `revokeByGrantId`

- [ ] **Step 1: Write the complete failing adapter contract suite**

For each enabled model (`Session`, `AccessToken`, `AuthorizationCode`,
`RefreshToken`, `Grant`, `Interaction`, `Client`, `RegistrationAccessToken`,
`ReplayDetection`) test upsert/find/expiry/destroy. Separately test
consumption, grant-wide revocation, user-code lookup, UID lookup, restart
persistence, and concurrent upsert.

Assert raw IDs, raw tokens, user codes, and UIDs do not appear in database
rows; store `sha256(model + ":" + id)` lookup keys.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/oidc-adapter.test.ts
```

Expected: FAIL because the adapter is absent.

- [ ] **Step 3: Implement the adapter with atomic SQL**

Use `INSERT ... ON DUPLICATE KEY UPDATE`, compare `expires_at > UTC_TIMESTAMP(6)`
in every find, set `consumed_at` only once, and delete by indexed grant ID in a
transaction. Convert provider payloads to/from JSON without mutating them.

- [ ] **Step 4: Run the adapter suite twice**

```bash
npx vitest run test/integration/oidc-adapter.test.ts
npx vitest run test/integration/oidc-adapter.test.ts
```

Expected: both runs PASS; the second run proves cleanup and isolation.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/auth/oidc-adapter.ts \
  data/Dockerfiles/mcp/test/integration/oidc-adapter.test.ts
git commit -m "feat: persist OAuth models in MariaDB"
```

---

### Task 4: Provider policy, key persistence, and restricted registration

**Files:**
- Create: `data/Dockerfiles/mcp/src/auth/oidc-provider.ts`
- Create: `data/Dockerfiles/mcp/src/auth/signing-keys.ts`
- Create: `data/Dockerfiles/mcp/src/http/rate-limit.ts`
- Create: `data/Dockerfiles/mcp/test/integration/oauth-policy.test.ts`
- Modify: `data/Dockerfiles/mcp/src/app.ts`

**Interfaces:**
- Produces: `createOidcProvider(deps): Promise<Provider>`
- Produces: `validateDynamicClient(metadata, allowedRedirectUris): void`
- Produces routes: `/oauth/auth`, `/oauth/token`, `/oauth/reg`,
  `/oauth/revocation`, `/oauth/jwks`, discovery

- [ ] **Step 1: Write failing OAuth policy tests**

Test discovery, two-minute codes, 15-minute opaque access tokens, 30-day
rotating refresh tokens, PKCE omission/plain rejection, S256 success,
resource/audience enforcement, revocation, and persistence across provider
restart.

Post DCR bodies that must be rejected:

```json
{"redirect_uris":["https://evil.example/cb"]}
{"redirect_uris":["https://claude.ai/api/mcp/auth_callback/extra"]}
{"grant_types":["client_credentials"]}
{"response_types":["token"]}
{"token_endpoint_auth_method":"client_secret_basic"}
```

Only the exact configured callback, a grant-type set containing
`authorization_code` and no value outside
`authorization_code|refresh_token`, response type code, and auth method none
is accepted. A valid registration that omits `refresh_token` is normalized to
store both allowed grants so issued rotating refresh tokens remain usable.
Send eleven registration attempts from one IP and require the eleventh to
return 429.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/oauth-policy.test.ts
```

Expected: FAIL because no provider is mounted.

- [ ] **Step 3: Implement provider configuration**

Configure:

```ts
{
  adapter: MariaDbOidcAdapter.factory(pool),
  pkce: { required: () => true },
  responseTypes: ["code"],
  clientDefaults: {
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  },
  formats: { AccessToken: "opaque" },
  ttl: {
    AccessToken: 900,
    AuthorizationCode: 120,
    RefreshToken: 2592000,
    Interaction: 600,
    Session: 2592000
  },
  issueRefreshToken: () => true,
  rotateRefreshToken: true,
  routes: {
    authorization: "/oauth/auth",
    token: "/oauth/token",
    registration: "/oauth/reg",
    revocation: "/oauth/revocation",
    jwks: "/oauth/jwks"
  }
}
```

Enable only registration, revocation, and resource indicators. Return resource
server info only for the exact MCP URL and its three scopes. Parse and validate
the `/reg` JSON in provider middleware before its registration action; pin the
provider version and keep a contract test because this integration deliberately
uses the provider's documented upstream-body fallback.

Generate an asymmetric signing JWK once, encrypt its private material with
record type `oidc-signing-key`, store it in `service_state`, and reuse it after
restart.

- [ ] **Step 4: Run OAuth policy and adapter suites**

```bash
npx vitest run test/integration/oauth-policy.test.ts \
  test/integration/oidc-adapter.test.ts
```

Expected: PASS with exact redirect and PKCE enforcement.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/auth data/Dockerfiles/mcp/src/http \
  data/Dockerfiles/mcp/src/app.ts data/Dockerfiles/mcp/test
git commit -m "feat: enforce MCP OAuth policy"
```

---

### Task 5: App-password verification, login, and consent interactions

**Files:**
- Create: `data/Dockerfiles/mcp/src/auth/credential-verifier.ts`
- Create: `data/Dockerfiles/mcp/src/auth/interactions.ts`
- Create: `data/Dockerfiles/mcp/test/unit/credential-verifier.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/interactions.test.ts`
- Modify: `data/Dockerfiles/mcp/src/app.ts`

**Interfaces:**
- Produces: roadmap `CredentialVerifier`
- Produces routes: `GET|POST /mcp-login/:interaction`

- [ ] **Step 1: Write failing dual-protocol and interaction tests**

Inject fake IMAP/SMTP authenticators and require both calls to use:

```ts
{
  username: "user@example.test",
  password: "app-password",
  host: "dovecot-mailcow" | "postfix-mailcow",
  servername: "mail.example.test",
  rejectUnauthorized: true
}
```

Test IMAP fail, SMTP fail, both success, generic error copy, five login failures
per IP/mailbox followed by 429, CSRF mismatch, unallowlisted return URL, secure
cookie flags, consent limited to the three scopes, consent reuse, explicit grant
revocation, and no secret in HTML/logs.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/credential-verifier.test.ts \
  test/integration/interactions.test.ts
```

Expected: FAIL because verification and interaction routes are absent.

- [ ] **Step 3: Implement login and consent**

Use ImapFlow STARTTLS on port 143 and Nodemailer SMTP submission with
`requireTLS: true` on port 587. Force IMAP
`auth.loginMethod="AUTH=PLAIN"` and Nodemailer `authMethod="PLAIN"`. Mount
mailcow certificate material read-only and use it as an explicit trust source
while keeping `servername=MAILCOW_HOSTNAME`.

On dual success, call `AccountRepository.upsertVerified`, then finish login:

```ts
await provider.interactionFinished(req, res, {
  login: { accountId },
}, { mergeWithLastSubmission: false });
```

For consent, create/update `provider.Grant`, add only requested allowed scopes
for the exact resource, persist consent metadata, and finish with
`{ consent: { grantId } }`. Render server-side HTML with escaped values, CSRF
tokens, CSP, no third-party assets, and uniquely named Secure/HttpOnly/Lax
cookies.

The login copy explicitly requires a dedicated mailcow app password restricted
to IMAP and SMTP and explains that the service cannot distinguish a primary
password from an app password through these protocols.

- [ ] **Step 4: Run auth tests and inspect logs**

```bash
npx vitest run test/unit/credential-verifier.test.ts \
  test/integration/interactions.test.ts \
  test/integration/oauth-policy.test.ts
```

Expected: PASS and the captured logs contain neither mailbox passwords nor
OAuth artifacts.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/auth data/Dockerfiles/mcp/src/app.ts \
  data/Dockerfiles/mcp/test
git commit -m "feat: authorize MCP users with app passwords"
```

---

### Task 6: Protected-resource metadata and authenticated Streamable HTTP

**Files:**
- Create: `data/Dockerfiles/mcp/src/auth/token-verifier.ts`
- Create: `data/Dockerfiles/mcp/src/http/metadata.ts`
- Create: `data/Dockerfiles/mcp/src/mcp/context.ts`
- Create: `data/Dockerfiles/mcp/src/mcp/server.ts`
- Create: `data/Dockerfiles/mcp/src/mcp/transport.ts`
- Create: `data/Dockerfiles/mcp/test/integration/mcp-auth.test.ts`
- Modify: `data/Dockerfiles/mcp/src/app.ts`

**Interfaces:**
- Produces: `verifyAccessToken(token): Promise<AuthInfo>`
- Produces: `requireAccountContext(authInfo, requiredScope): AccountContext`
- Produces account-bound MCP `POST|GET|DELETE` at `/mcp`

- [ ] **Step 1: Write failing metadata and bearer tests**

Require:

```text
GET /.well-known/oauth-protected-resource/mcp -> resource metadata
POST /mcp without token -> 401 + resource_metadata challenge
expired/wrong audience token -> 401
valid token missing scope -> 403 + insufficient_scope challenge
valid token -> MCP initialize/tools-list response
mailbox address absent from token and result
```

Also submit a fabricated `mcp-session-id` without a bearer token and require
401, proving session IDs are never authentication. Initialize a session as
account A, then reuse its session ID with account B's valid bearer token and
require 403 plus session termination.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/mcp-auth.test.ts
```

Expected: FAIL because bearer verification and MCP transport are absent.

- [ ] **Step 3: Implement metadata, verifier, and transport**

Resolve opaque tokens through `provider.AccessToken.find()`, validate expiry,
client, resource/audience, account ID, and scopes, then return:

```ts
{
  token,
  clientId,
  scopes,
  expiresAt,
  resource: new URL(config.resource),
  extra: { accountId }
}
```

Use `mcpAuthMetadataRouter` and `requireBearerAuth` from SDK 1.29. For an
authenticated initialize request, create a `McpServer` and:

```ts
new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
  onsessioninitialized: (sessionId) => sessions.set(sessionId, {
    server,
    transport,
    accountId,
    clientId,
    expiresAt: authInfo.expiresAt
  })
});
```

Before every POST, GET, or DELETE using a session ID, validate the bearer token
again and compare its account/client to the stored session record. A session ID
alone is never accepted. Close sessions on DELETE, transport close, token
expiry, or 30 minutes of inactivity. In-memory sessions are intentionally
single-container and non-durable; clients reinitialize after restart. Register
no mail tools yet.

- [ ] **Step 4: Run complete Phase 2 gate**

```bash
cd data/Dockerfiles/mcp
npm run typecheck
npm test
npm run build
cd ../../..
COMPOSE_PROFILES=mcp docker compose config -q
git diff --check
```

Expected: all Phase 1 and Phase 2 suites PASS.

- [ ] **Step 5: Commit and stop for review**

```bash
git add data/Dockerfiles/mcp
git commit -m "feat: protect Streamable HTTP MCP endpoint"
```

Review gate: complete an authorization-code flow with a test public client,
restart the service, refresh the token, and prove the same grant remains usable
before starting Phase 3.
