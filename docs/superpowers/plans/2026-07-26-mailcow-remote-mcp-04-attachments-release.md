# Mailcow Remote MCP Phase 4: Attachments and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe attachment download/upload/forwarding, an MCP App file
picker with standalone fallback, complete MIME size enforcement, and final
Claude/update/backup release verification.

**Architecture:** Keep attachment metadata and one-way token hashes in
MariaDB, while streaming encrypted bytes to the dedicated temporary volume.
Uploads enter through account-bound one-time tokens and are validated by
extension, declared MIME, magic bytes, and bounded OOXML inspection. SMTP
streams staged or existing-message attachments into MIME without exposing
local paths.

**Tech Stack:** Busboy, file-type, yauzl, MailParser/Nodemailer, MCP Apps
extension 1.7, Node streams/crypto, Vitest, Playwright-compatible browser tests.

## Global Constraints

- Apply every constraint in
  [the roadmap](2026-07-26-mailcow-remote-mcp-00-roadmap.md#global-constraints).
- Allowed initial types are exactly `pdf,xlsx,csv,txt,png,jpg,jpeg`.
- Reject `.xls`, macro-enabled Office files, scripts, executables, device
  files, archive masquerading, and malformed OOXML.
- Upload tokens are random, account-bound, single-purpose, one-hour,
  single-use, and stored only as SHA-256 hashes.
- Never log path tokens; browser flow exchanges a path token for a short-lived
  Secure/HttpOnly/SameSite=Strict cookie and redirects to a tokenless path.
- A successful send deletes staged files immediately; failed sends retain them
  only to original expiry.

---

### Task 1: Stream-encrypted staging store and attachment repository

**Files:**
- Create: `data/Dockerfiles/mcp/src/db/migrations/003_attachments.sql`
- Create: `data/Dockerfiles/mcp/src/attachments/repository.ts`
- Create: `data/Dockerfiles/mcp/src/attachments/staging-store.ts`
- Create: `data/Dockerfiles/mcp/test/unit/staging-store.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/attachment-repository.test.ts`

**Interfaces:**
- Produces roadmap `AttachmentStore` and `StagedAttachment`
- Produces tables: `upload_tokens`, `attachments`

- [ ] **Step 1: Write failing storage/repository tests**

The migration test requires these columns and indexes:

```text
upload_tokens: token_hash, account_id, purpose, expires_at, consumed_at,
               created_at
attachments: id, account_id, filename, declared_mime, detected_mime, size_bytes,
             sha256, storage_ref_envelope, state, expires_at, consumed_at,
             created_at
indexes: unique token_hash; account/expiry; account/state/expiry
```

Stream a multi-chunk binary fixture and assert round-trip bytes/hash, ciphertext
does not contain plaintext, unique nonces, wrong-account/wrong-key/tamper
failure, partial-upload cleanup, atomic final rename, state transition
`ready -> sending -> consumed`, and expired-row/file cleanup.

Ensure supplied filenames such as `../../x.pdf`, NUL, slash, and backslash are
labels only and never influence filesystem paths.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/staging-store.test.ts \
  test/integration/attachment-repository.test.ts
```

Expected: FAIL because storage modules are absent.

- [ ] **Step 3: Implement streaming AES-GCM storage**

Use random UUID filenames under the fixed configured volume root. File format:

```text
8-byte magic "MCPATT01" | 12-byte nonce | ciphertext | 16-byte GCM tag
```

AAD is `mailcow-mcp:v1:staged-attachment:<accountId>:<attachmentId>`. Encrypt
the random storage reference separately with record type
`attachment-storage-ref`. Write to
an adjacent `.partial` file with mode `0600`, finalize the tag, fsync, rename,
then insert metadata. On any failure remove the partial file and row. Opening
validates ownership/state/tag before yielding bytes.

- [ ] **Step 4: Run storage tests**

```bash
npx vitest run test/unit/staging-store.test.ts \
  test/integration/attachment-repository.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/attachments data/Dockerfiles/mcp/test
git commit -m "feat: stage encrypted MCP attachments"
```

---

### Task 2: File classification and bounded OOXML validation

**Files:**
- Create: `data/Dockerfiles/mcp/src/attachments/validation.ts`
- Create: `data/Dockerfiles/mcp/test/unit/attachment-validation.test.ts`
- Add fixtures: `data/Dockerfiles/mcp/test/fixtures/files/*`

**Interfaces:**
- Produces:

```ts
export async function validateUpload(
  path: string,
  declared: { filename: string; mimeType: string },
  limits: { maxBytes: number; allowedTypes: ReadonlySet<string> },
): Promise<UploadMetadata>;
```

- [ ] **Step 1: Create deterministic fixtures and failing matrix tests**

Fixtures include valid PDF/PNG/JPEG/CSV/TXT/XLSX, truncated PDF, PNG renamed
`.pdf`, ZIP renamed `.xlsx`, XLSX missing `[Content_Types].xml`, macro-enabled
workbook, `.xls`, ELF/PE/script, ZIP bomb metadata, too many ZIP entries, and
over-limit input.

Require all three signals—normalized extension, declared MIME, detected
signature—to agree. Text/CSV must be valid UTF-8 without NUL.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/attachment-validation.test.ts
```

Expected: FAIL because `validateUpload` is absent.

- [ ] **Step 3: Implement classifiers and OOXML bounds**

For XLSX, lazily inspect ZIP central directory with yauzl and require:

```text
[Content_Types].xml
_rels/.rels
xl/workbook.xml
```

Reject `vbaProject.bin`, external path traversal, encrypted entries, more than
10,000 entries, any declared uncompressed entry over 50 MiB, or aggregate
declared uncompressed size over 200 MiB. Do not extract the workbook.

- [ ] **Step 4: Run validation and storage tests**

```bash
npx vitest run test/unit/attachment-validation.test.ts \
  test/unit/staging-store.test.ts
```

Expected: every valid fixture passes and every adversarial fixture returns
`attachment_rejected`.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/attachments \
  data/Dockerfiles/mcp/test/fixtures/files \
  data/Dockerfiles/mcp/test/unit/attachment-validation.test.ts
git commit -m "feat: validate MCP attachment types"
```

---

### Task 3: One-time upload tokens, multipart API, and standalone form

**Files:**
- Create: `data/Dockerfiles/mcp/src/attachments/upload-tokens.ts`
- Create: `data/Dockerfiles/mcp/src/http/uploads.ts`
- Create: `data/Dockerfiles/mcp/test/integration/uploads.test.ts`
- Modify: `data/Dockerfiles/mcp/src/app.ts`
- Modify: `data/conf/nginx/templates/sites-default.conf.j2`

**Interfaces:**
- Produces:

```ts
issue(accountId: string, purpose: "app" | "browser" | "api"): Promise<string>
consume(
  rawToken: string,
  purpose: "app" | "browser" | "api",
): Promise<{ accountId: string }>
```

- Produces: `GET|POST /mcp-upload/:token` and tokenless
  `GET|POST /mcp-upload/session`

- [ ] **Step 1: Write failing token and HTTP tests**

Test SHA-256-only storage, purpose/account/expiry binding, concurrent
single-consumption, five active uploads/account, streaming 10 MiB boundary,
aggregate message boundary, aborted multipart cleanup, cookie exchange,
tokenless redirect, CSRF, no-referrer, no third-party assets, and no token in
captured application/nginx-style logs.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/uploads.test.ts
```

Expected: FAIL because upload token/routes are absent.

- [ ] **Step 3: Implement token consumption and streaming multipart**

Generate 32 random bytes and return base64url. Store:

```ts
sha256(Buffer.concat([
  Buffer.from("mailcow-mcp:upload-token:v1:"),
  Buffer.from(rawToken)
]))
```

Use a transaction with `SELECT ... FOR UPDATE` for first consumption. Busboy
streams one `file` part to an adjacent temporary file while hashing/counting;
reject additional file parts. Validate then stream-encrypt into
`AttachmentStore`.

Browser GET consumes the path token into a two-minute opaque session cookie,
redirects 303 to `/mcp-upload/session`, and renders escaped server-side HTML.
Add `Referrer-Policy: no-referrer`, restrictive CSP, CSRF, Secure/HttpOnly/
SameSite=Strict cookie, and `Cache-Control: no-store`.

- [ ] **Step 4: Run upload tests and nginx render tests**

```bash
npx vitest run test/integration/uploads.test.ts
cd ../../nginx
python3 -m unittest test_bootstrap.py
```

Expected: PASS; raw path tokens are absent from all captured logs.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp data/conf/nginx/templates/sites-default.conf.j2
git commit -m "feat: add secure MCP attachment uploads"
```

---

### Task 4: Attachment MCP tools, resource reads, and MCP App picker

**Files:**
- Create: `data/Dockerfiles/mcp/src/mcp/tools/attachments.ts`
- Create: `data/Dockerfiles/mcp/src/attachments/upload-app.html`
- Create: `data/Dockerfiles/mcp/test/unit/attachment-tools.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/upload-app.test.ts`
- Modify: `data/Dockerfiles/mcp/src/mcp/server.ts`

**Interfaces:**
- Produces tools: `create_attachment_upload`, `upload_attachment_base64`
- Produces resources: `ui://mailcow/upload-attachment`,
  `mailcow-attachment://<opaque-id>`

- [ ] **Step 1: Write failing MCP tool/resource tests**

Require base64 decoded limit 1 MiB, strict filename/MIME/data schema, account
ownership, attachment metadata without bytes in `get_message`, and
`resources/read` returning text or base64 `BlobResourceContents` only to the
owning account.

For Apps-capable client capabilities, assert tool metadata contains:

```json
{"ui":{"resourceUri":"ui://mailcow/upload-attachment"}}
```

and the upload token appears only in result `_meta`. For a client without the
MCP Apps extension, assert a separately issued browser fallback URL appears in
text. Both modes must retain meaningful text content.

Test `upload-app.html` itself in a real browser context with Playwright
against a stubbed MCP App postMessage bridge: assert file selection, a direct
POST to the issued same-origin upload URL, progress and error rendering, and
zero third-party requests.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/attachment-tools.test.ts \
  test/integration/upload-app.test.ts
```

Expected: FAIL because tools/resources are absent.

- [ ] **Step 3: Implement tools and a self-contained MCP App**

Use `registerAppTool`, `registerAppResource`, and `RESOURCE_MIME_TYPE` from
`@modelcontextprotocol/ext-apps/server`. The HTML contains only inline CSS/JS,
an `<input type=file>`, progress, cancel, success, and accessible error state.
It reads client-only result metadata through the MCP App bridge and POSTs the
file directly to the issued same-server upload URL.

Advertise a CSP with only the exact mailcow HTTPS origin in `connectDomains`;
no resource/frame domains or browser permissions. At tool-call time, pass
`server.server.getClientCapabilities()` to `getUiCapability`; Phase 2's
account-bound stateful transport preserves the initialize capabilities needed
to choose client-only App metadata versus browser fallback output.

- [ ] **Step 4: Run tool/App tests**

```bash
npx vitest run test/unit/attachment-tools.test.ts \
  test/integration/upload-app.test.ts \
  test/integration/uploads.test.ts
```

Expected: PASS, including PDF and XLSX picker uploads.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src/mcp \
  data/Dockerfiles/mcp/src/attachments/upload-app.html \
  data/Dockerfiles/mcp/test
git commit -m "feat: expose MCP attachment upload tools"
```

---

### Task 5: MIME attachments, existing-message forwarding, and size enforcement

**Files:**
- Modify: `data/Dockerfiles/mcp/src/mail/mime.ts`
- Modify: `data/Dockerfiles/mcp/src/mcp/tools/send.ts`
- Modify: `data/Dockerfiles/mcp/src/mail/imap-gateway.ts`
- Create: `data/Dockerfiles/mcp/test/unit/send-attachments.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/attachment-roundtrip.test.ts`

**Interfaces:**
- Extends `send_email` with `attachment_ids: string[]`
- Consumes staged IDs and existing `mailcow-attachment://` handles

- [ ] **Step 1: Write failing MIME/round-trip tests**

Cover PDF/XLSX SHA-256 round trips, text+HTML+multiple attachments, filename
encoding, staged ownership/expiry/state, existing-message part forwarding,
mixed staged/existing attachments, 25 MiB encoded boundary, base64 expansion,
partial SMTP rejection, successful cleanup, failed-send retention, and
ambiguous outcome without retry or premature deletion.

- [ ] **Step 2: Run and verify red**

```bash
cd data/Dockerfiles/mcp
npx vitest run test/unit/send-attachments.test.ts \
  test/integration/attachment-roundtrip.test.ts
```

Expected: FAIL because `send_email` does not accept attachments.

- [ ] **Step 3: Implement streaming MIME and state transitions**

Before SMTP, resolve every attachment, sum raw sizes, calculate base64 line
expansion plus MIME/header overhead, and reject predicted oversize. Atomically
mark staged rows `sending`; stream staged plaintext or IMAP part streams into
Nodemailer attachments.

On definitive SMTP success call `consume` for each staged item. On definitive
failure return each to `ready` without extending expiry. On ambiguous outcome
leave `sending`; a cleanup job changes it to expired after the original TTL,
never to reusable.

- [ ] **Step 4: Run attachment send and regression suites**

```bash
npx vitest run test/unit/send-attachments.test.ts \
  test/integration/attachment-roundtrip.test.ts \
  test/unit/send-tool.test.ts
```

Expected: PASS with matching received-file digests.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp/src data/Dockerfiles/mcp/test
git commit -m "feat: send and forward MCP attachments"
```

---

### Task 6: Final security, update, backup, and Claude release gate

**Files:**
- Create: `data/Dockerfiles/mcp/test/integration/security-boundaries.test.ts`
- Create: `data/Dockerfiles/mcp/test/integration/claude-checklist.md`
- Modify: `docs/manual-guides/MCP.md`
- Modify: `helper-scripts/backup_and_restore.sh` only if its physical MariaDB
  backup test shows the MCP database is omitted
- Modify: `.github/workflows/image_builds.yml`

**Interfaces:**
- Produces release candidate `ghcr.io/mailcow/mcp:0.1.0`

- [ ] **Step 1: Add failing release-boundary checks**

Automate cross-account attempts for every handle/tool/resource/upload path,
header injection, SSRF URL fields, path traversal, oversized streams,
credential/token/log redaction, missing-key fail-closed, database restart,
revocation, and MCP service failure while nginx/UI remain healthy.

Extend lifecycle fixtures to simulate an old deployment updating, answering
yes/no, forced update, enabled later update with a failed migration, disable,
re-enable, and confirmed purge.

- [ ] **Step 2: Run the full automated gate and record failures**

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
python3 -m unittest data/Dockerfiles/nginx/test_bootstrap.py
cd data/Dockerfiles/mcp
npm ci
npm run typecheck
npm test
npm run build
cd ../../..
COMPOSE_PROFILES= docker compose config -q
COMPOSE_PROFILES=mcp docker compose config -q
git diff --check
```

Expected before final hardening: at least the newly added security-boundary
suite fails on each unimplemented release assertion.

- [ ] **Step 3: Close every concrete release assertion**

Make only changes demanded by failing assertions. Documentation must include:

```text
enable/status/disable/purge commands
app-password creation with only IMAP and SMTP enabled
Claude connector URL
OAuth redirect allowlist configuration
attachment limits and allowed types
mailcow.conf and MariaDB backup/restore requirements
key-loss warning
update --force/--skip-start behavior
recovery after failed MCP migration
prompt-injection threat model and reliance on client-side send confirmation
```

Do not claim the MCP temp volume is durable backup data. Confirm the existing
physical MariaDB backup includes `mailcow_mcp`; change backup code only if the
test disproves that.

- [ ] **Step 4: Run the full automated gate again**

Run the exact Step 2 command. Expected: zero failed tests, both Compose states
valid, and clean diff hygiene.

- [ ] **Step 5: Perform the manual Claude checklist**

Against a disposable public test hostname:

```text
discover protected resource -> register client -> PKCE login -> consent
refresh after service restart
list/search/read/create folder/move to Trash and Junk
send text+HTML reply with CC/BCC
verify the sent message appears in the mailbox Sent folder
upload PDF and XLSX through inline App
upload through standalone form
upload 1 MiB base64 generated file
download/forward existing attachment
revoke app password and observe reauthentication_required
disconnect/revoke grant
```

Record date, Claude client version, image digest, and pass/fail beside every
item in `test/integration/claude-checklist.md`. Do not mark release-ready with
an unchecked item.

- [ ] **Step 6: Commit and request final review**

```bash
git add data/Dockerfiles/mcp helper-scripts .github/workflows \
  docs/manual-guides/MCP.md
git commit -m "feat: complete remote mailcow MCP service"
```

After the commit, invoke `superpowers:requesting-code-review`, address review
through `superpowers:receiving-code-review`, rerun the complete gate, and use
`superpowers:finishing-a-development-branch` for integration. Do not publish
the version tag until the manual Claude checklist and final review both pass.
