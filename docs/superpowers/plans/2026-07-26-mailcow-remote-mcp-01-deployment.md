# Mailcow Remote MCP Phase 1: Deployment Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a disabled-by-default MCP container skeleton plus automatic
configuration migration, profiled Compose wiring, conditional nginx routing,
and transactional lifecycle helpers.

**Architecture:** Build a minimal TypeScript service with strict configuration,
health endpoints, and database bootstrap commands. Integrate it through tracked
mailcow files and make `COMPOSE_PROFILES=mcp` the only desired-state flag.
Shell and nginx behavior are tested with isolated fixtures before any real
Compose mutation.

**Tech Stack:** Node.js 24.18, TypeScript 7, Express 5, Vitest, mysql2, Docker
Compose profiles, Bash, Python/Jinja nginx bootstrap.

## Global Constraints

- Apply every constraint in
  [the roadmap](2026-07-26-mailcow-remote-mcp-00-roadmap.md#global-constraints).
- This phase exposes only `/health/live`, `/health/ready`, and placeholder
  unauthenticated `/mcp` behavior; OAuth and tools arrive in later phases.
- The profile remains disabled after both `generate_config.sh` and migration of
  an old installation.
- All configuration edits are atomic and retain `0600`.
- A failed enable restores the exact previous `mailcow.conf` and nginx state.

---

### Task 1: Service scaffold, strict configuration, and container health

**Files:**
- Create: `data/Dockerfiles/mcp/package.json`
- Create: `data/Dockerfiles/mcp/package-lock.json`
- Create: `data/Dockerfiles/mcp/tsconfig.json`
- Create: `data/Dockerfiles/mcp/vitest.config.ts`
- Create: `data/Dockerfiles/mcp/src/config.ts`
- Create: `data/Dockerfiles/mcp/src/app.ts`
- Create: `data/Dockerfiles/mcp/src/server.ts`
- Create: `data/Dockerfiles/mcp/test/unit/config.test.ts`
- Create: `data/Dockerfiles/mcp/test/unit/app.test.ts`
- Create: `data/Dockerfiles/mcp/Dockerfile`

**Interfaces:**
- Produces: `loadConfig(env: NodeJS.ProcessEnv): AppConfig`
- Produces: `createApp(deps: { readiness(): Promise<boolean> }): Express`
- Produces: container commands `server`, `db:init`, and `db:migrate`

- [ ] **Step 1: Create package metadata and the failing configuration test**

Use the exact direct dependency pins from the roadmap and scripts:

```json
{
  "type": "module",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run",
    "server": "node dist/server.js",
    "db:init": "node dist/db/init.js",
    "db:migrate": "node dist/db/migrations.js"
  }
}
```

Write `config.test.ts` to assert a valid 64-hex key parses, a 63-character key
throws `MCP_ENCRYPTION_KEY must be 64 hexadecimal characters`, and an empty
database password throws without echoing its value.

- [ ] **Step 2: Run the unit test and verify red**

Run:

```bash
cd data/Dockerfiles/mcp
npm ci
npx vitest run test/unit/config.test.ts
```

Expected: FAIL because `src/config.ts` does not exist.

- [ ] **Step 3: Implement the minimal typed configuration and health app**

Define:

```ts
export interface AppConfig {
  hostname: string;
  issuer: URL;
  resource: URL;
  port: number;
  db: { host: string; name: string; user: string; password: string };
  encryptionKey: Buffer;
}

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig;
export function createApp(
  deps: { readiness(): Promise<boolean> },
): import("express").Express;
```

`GET /health/live` returns `200 {"status":"live"}`. `GET /health/ready` returns
200 only when `readiness()` resolves true, otherwise 503. The placeholder
`POST /mcp` returns 401 and:

```http
WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource/mcp"
```

Use a two-stage Dockerfile with
`node:24.18.0-alpine3.24`, `npm ci`, non-root UID/GID `10001`, read-only
application files, `NODE_ENV=production`, and a `HEALTHCHECK` against
`http://127.0.0.1:3000/health/ready`.

- [ ] **Step 4: Run focused tests, typecheck, and image build**

Run:

```bash
cd data/Dockerfiles/mcp
npm run typecheck
npm test
docker build -t mailcow/mcp:test .
```

Expected: all tests PASS and the image builds.

- [ ] **Step 5: Commit**

```bash
git add data/Dockerfiles/mcp
git commit -m "feat: scaffold mailcow MCP service"
```

---

### Task 2: Atomic generation and migration of MCP configuration

**Files:**
- Modify: `generate_config.sh`
- Modify: `_modules/scripts/new_options.sh`
- Create: `_modules/scripts/mcp_config.sh`
- Create: `helper-scripts/dev_tests/test_mcp_config.sh`

**Interfaces:**
- Produces: `mcp_prepare_config <mailcow.conf> <new|upgrade>`
- Produces: `mcp_profile_contains <comma-list> <token>`
- Produces: `mcp_profile_add <comma-list> <token>`
- Produces: `mcp_profile_remove <comma-list> <token>`
- Produces: `mcp_validate_config <mailcow.conf> <enabled|disabled>`

- [ ] **Step 1: Write fixture-driven failing shell tests**

The test script creates a temporary old `mailcow.conf`, calls
`mcp_prepare_config`, and asserts:

```bash
grep -Eq '^MCP_DBPASS=[0-9a-f]{64}$' "${case_dir}/mailcow.conf"
grep -Eq '^MCP_ENCRYPTION_KEY=[0-9a-f]{64}$' "${case_dir}/mailcow.conf"
grep -qx 'MCP_CONFIG_VERSION=1' "${case_dir}/mailcow.conf"
grep -qx 'MCP_UPDATE_OFFERED=0' "${case_dir}/mailcow.conf"
test "$(stat -c '%a' "${case_dir}/mailcow.conf" 2>/dev/null ||
  stat -f '%Lp' "${case_dir}/mailcow.conf")" = 600
```

It then hashes both secret lines, reruns migration, and requires identical
hashes. Add cases for marker-with-missing-key failure, preserving
`COMPOSE_PROFILES=foo,bar`, exact token add/remove, interruption before atomic
rename, and new-install `MCP_UPDATE_OFFERED=1`.

- [ ] **Step 2: Run the shell suite and verify red**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
```

Expected: FAIL because `_modules/scripts/mcp_config.sh` is absent.

- [ ] **Step 3: Implement atomic config helpers and wire generators**

Use `mktemp` in the same directory as the target, `umask 077`, copy current
content, append values to the temporary file, `chmod 600`, and `mv` only after
validation. Generate secrets with:

```bash
LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
```

Write `MCP_CONFIG_VERSION` after both secrets. Add all roadmap options to
`generate_config.sh` and `CONFIG_ARRAY`; delegate MCP-specific cases to
`mcp_prepare_config` rather than duplicating generation logic. Never print
secret values.

- [ ] **Step 4: Run shell tests and syntax checks**

Run:

```bash
bash -n generate_config.sh _modules/scripts/new_options.sh \
  _modules/scripts/mcp_config.sh helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_config.sh
```

Expected: syntax checks exit zero and every fixture reports PASS.

- [ ] **Step 5: Commit**

```bash
git add generate_config.sh _modules/scripts/new_options.sh \
  _modules/scripts/mcp_config.sh helper-scripts/dev_tests/test_mcp_config.sh
git commit -m "feat: migrate MCP configuration safely"
```

---

### Task 3: Profiled Compose service, database bootstrap, and migrations

**Files:**
- Modify: `docker-compose.yml`
- Create: `data/Dockerfiles/mcp/src/db/pool.ts`
- Create: `data/Dockerfiles/mcp/src/db/init.ts`
- Create: `data/Dockerfiles/mcp/src/db/migrations.ts`
- Create: `data/Dockerfiles/mcp/src/db/migrations/001_initial.sql`
- Create: `data/Dockerfiles/mcp/test/integration/db-bootstrap.test.ts`
- Modify: `data/Dockerfiles/mcp/package-lock.json`

**Interfaces:**
- Produces: Compose services `mcp-db-init` and `mcp-mailcow`
- Produces: named volume `mcp-attachments-vol-1`
- Produces: `createPool(config): Pool`
- Produces: `runMigrations(pool): Promise<void>`

- [ ] **Step 1: Write failing database bootstrap integration test**

Use `testcontainers@12.0.4` to start MariaDB with a root password. Invoke
`initializeDatabase()` twice, then query:

```sql
SELECT SCHEMA_NAME
FROM INFORMATION_SCHEMA.SCHEMATA
WHERE SCHEMA_NAME = 'mailcow_mcp';
SHOW GRANTS FOR 'mailcow_mcp'@'%';
```

Assert one schema exists and grants contain only
`` `mailcow_mcp`.* ``. Run `runMigrations()` twice and assert
`schema_migrations.version=1`.

- [ ] **Step 2: Run the integration test and verify red**

Run:

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/db-bootstrap.test.ts
```

Expected: FAIL because database bootstrap functions are absent.

- [ ] **Step 3: Implement bootstrap, migration runner, and Compose wiring**

Validate `MCP_DBNAME` and `MCP_DBUSER` against
`^[A-Za-z_][A-Za-z0-9_]{0,63}$` before interpolating identifiers. Parameterize
password values. The initial migration contains `schema_migrations` and a
minimal `service_state` table; OAuth tables arrive in Phase 2.

Add both services under:

```yaml
profiles: ["mcp"]
```

Use `mailcow/mcp:test` until Task 6. `mcp-db-init` receives `DBROOT` and exits.
`mcp-mailcow` receives only `MCP_DB*`, mounts
`mcp-attachments-vol-1:/var/lib/mailcow-mcp/attachments`, and depends on the
initializer's successful completion plus MariaDB health. No core service
depends on either MCP service.

- [ ] **Step 4: Verify database and Compose behavior**

Run:

```bash
cd data/Dockerfiles/mcp
npx vitest run test/integration/db-bootstrap.test.ts
cd ../../..
COMPOSE_PROFILES= docker compose config -q
COMPOSE_PROFILES=mcp docker compose config -q
COMPOSE_PROFILES= docker compose config --services | \
  grep -q '^mcp-mailcow$' && exit 1 || true
COMPOSE_PROFILES=mcp docker compose config --services | \
  grep -qx 'mcp-mailcow'
```

Expected: tests PASS; disabled service list omits MCP and enabled list includes
it.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml data/Dockerfiles/mcp
git commit -m "feat: add profiled MCP database services"
```

---

### Task 4: Conditional nginx routes that cannot break core nginx

**Files:**
- Modify: `docker-compose.yml`
- Modify: `data/Dockerfiles/nginx/bootstrap.py`
- Modify: `data/conf/nginx/templates/sites-default.conf.j2`
- Create: `data/Dockerfiles/nginx/test_bootstrap.py`

**Interfaces:**
- Produces: `profile_enabled(value: str, token: str) -> bool`
- Consumes: `COMPOSE_PROFILES` passed into `nginx-mailcow`

- [ ] **Step 1: Write failing Python tests for exact token parsing**

Cover:

```py
assert profile_enabled("mcp", "mcp")
assert profile_enabled("foo,mcp,bar", "mcp")
assert not profile_enabled("", "mcp")
assert not profile_enabled("mcp2,foo", "mcp")
assert not profile_enabled("foo,my-mcp", "mcp")
```

Render `sites-default.conf.j2` with `MCP_ENABLED` false and assert `/mcp` and
`/oauth/` are absent; render true and assert both are present.

- [ ] **Step 2: Run tests and verify red**

Run:

```bash
python3 -m unittest data/Dockerfiles/nginx/test_bootstrap.py
```

Expected: FAIL because `profile_enabled` and `MCP_ENABLED` do not exist.

- [ ] **Step 3: Implement template parsing and routes**

Pass `COMPOSE_PROFILES=${COMPOSE_PROFILES:-}` to nginx. Add
`MCP_ENABLED=profile_enabled(os.getenv("COMPOSE_PROFILES", ""), "mcp")` to the
Jinja context. Conditional routes cover only the paths in the approved spec.

Use request-time Docker DNS resolution:

```nginx
resolver 127.0.0.11 valid=10s ipv6=off;
set $mcp_upstream http://mcp-mailcow:3000;
proxy_pass $mcp_upstream;
```

Set forwarded host/scheme/IP, disable buffering for `/mcp`, suppress access-log
query/path tokens on `/mcp-upload/`, and apply explicit body/time limits.

- [ ] **Step 4: Verify Python, Jinja, and nginx syntax**

Run:

```bash
python3 -m unittest data/Dockerfiles/nginx/test_bootstrap.py
docker build -t mailcow/nginx-mcp:test data/Dockerfiles/nginx
docker compose config -q
```

Then render both template states in the Python test and run `nginx -t` inside
the test image with a stub upstream config. Expected: all commands PASS; nginx
starts even when `mcp-mailcow` does not resolve.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml data/Dockerfiles/nginx \
  data/conf/nginx/templates/sites-default.conf.j2
git commit -m "feat: add conditional MCP nginx routes"
```

---

### Task 5: Transactional lifecycle helper and update integration

**Files:**
- Create: `helper-scripts/mcp.sh`
- Create: `helper-scripts/dev_tests/test_mcp_lifecycle.sh`
- Modify: `update.sh`
- Modify: `_modules/scripts/core.sh`

**Interfaces:**
- Produces CLI: `mcp.sh enable|disable|status|retry|purge`
- Produces update functions:
  `mcp_update_preflight`, `mcp_update_offer`, `mcp_update_report`

- [ ] **Step 1: Write a failing command-stub lifecycle suite**

Place fake `docker` and `curl` executables first in `PATH`; each records calls
and can fail at a named stage. Test:

```text
enable success
enable idempotence
failure at config, pull, init, migration, app start, nginx recreate, discovery
disable twice
purge rejected without exact confirmation
preserve COMPOSE_PROFILES=foo,bar
force and skip-start never call enable
post-merge compose validation occurs
```

Each failure case compares `mailcow.conf` byte-for-byte with its pre-enable
copy and asserts the final nginx recreate ran with MCP disabled.

- [ ] **Step 2: Run the lifecycle suite and verify red**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
```

Expected: FAIL because `helper-scripts/mcp.sh` is absent.

- [ ] **Step 3: Implement the lifecycle state machine**

Use a lock directory with a trap, an adjacent mode-`0600` backup, and atomic
profile edits. `enable` executes:

```text
validate -> set desired profile -> compose config -> pull -> db init
-> restricted migration -> app start -> nginx recreate -> HTTPS verification
```

On failure, restore prior configuration, remove only newly created MCP
containers, and recreate nginx. `disable` preserves secrets/database/volume.
`purge` first requires disabled state and the exact typed confirmation
`PURGE mailcow_mcp`.

In `update.sh`, run MCP config preparation before the first Compose validation,
run a second `docker compose config -q` after merge, and make the one-time offer
only after core startup. Unset inherited `COMPOSE_PROFILES` before Compose
commands so `.env` remains authoritative.

- [ ] **Step 4: Run lifecycle and updater regression tests**

Run:

```bash
bash -n helper-scripts/mcp.sh update.sh _modules/scripts/core.sh
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
docker compose config -q
```

Expected: all fixtures PASS and no failure path calls `docker compose down` on
the core stack during MCP-only activation.

- [ ] **Step 5: Commit**

```bash
git add helper-scripts/mcp.sh helper-scripts/dev_tests \
  update.sh _modules/scripts/core.sh
git commit -m "feat: automate MCP lifecycle during updates"
```

---

### Task 6: Image build/publish workflow and phase gate

**Files:**
- Modify: `.github/workflows/image_builds.yml`
- Create: `.github/workflows/mcp_release.yml`
- Modify: `docker-compose.yml`
- Create: `docs/manual-guides/MCP.md`

**Interfaces:**
- Produces: multi-arch image `ghcr.io/mailcow/mcp:0.1.0`
- Consumes: the exact `mcp-v0.1.0` Git tag for publishing

- [ ] **Step 1: Add a failing workflow/Compose policy check**

Extend `test_mcp_lifecycle.sh` to assert:

```bash
grep -q 'ghcr.io/mailcow/mcp:0.1.0' docker-compose.yml
grep -q 'linux/amd64,linux/arm64' .github/workflows/mcp_release.yml
! grep -q 'image:.*latest' docker-compose.yml
```

Run it and expect failure while Compose still uses `mailcow/mcp:test`.

- [ ] **Step 2: Implement CI build and release**

Add `mcp-mailcow` to normal image build validation. The release workflow
triggers only on `mcp-v0.1.0`, uses `docker/build-push-action`, publishes
`linux/amd64,linux/arm64`, enables provenance/SBOM, and grants
`packages: write`. Change Compose to the exact version tag after the workflow
definition exists.

Document enable/status/disable/purge, automatic secret behavior, backup of
`mailcow.conf`, and the fact that ordinary updates never purge MCP data.

- [ ] **Step 3: Run the complete Phase 1 gate**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
python3 -m unittest data/Dockerfiles/nginx/test_bootstrap.py
cd data/Dockerfiles/mcp
npm ci && npm run typecheck && npm test && npm run build
cd ../../..
COMPOSE_PROFILES= docker compose config -q
COMPOSE_PROFILES=mcp docker compose config -q
git diff --check
```

Expected: all tests and both Compose states PASS.

- [ ] **Step 4: Commit and stop for review**

```bash
git add .github/workflows docker-compose.yml docs/manual-guides/MCP.md
git commit -m "ci: publish pinned mailcow MCP image"
```

Review gate: inspect the six Phase 1 commits and test an upgrade fixture before
starting Phase 2. Publishing the real tag requires a mailcow maintainer with
GHCR write authority; until then, do not deploy the operator-facing Compose
service outside a local test environment.
