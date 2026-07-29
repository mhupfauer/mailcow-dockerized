# Mailcow MCP service

> This branch contains implementation code for the MCP integration. Its release
> workflow is defined here, but no MCP image has been published and no operator
> stack has been deployed by this branch.

The MCP service is disabled by default. It is only active when
`COMPOSE_PROFILES` in `mailcow.conf` contains `mcp` as an exact comma-separated
token. When disabled, the profiled services and public MCP routes are absent.

## Configuration migration

On a new installation or the first MCP-aware update of an existing one,
mailcow adds the MCP configuration defaults to `mailcow.conf`. It automatically
creates `MCP_DBPASS` and `MCP_ENCRYPTION_KEY` as 64-character hexadecimal
secrets, retains mode `0600`, and does not print either secret. Once
`MCP_CONFIG_VERSION=1` exists, automatic migration preserves those secrets; it
does not silently replace a missing or invalid value.

Migration leaves MCP disabled. It also preserves existing unrelated Compose
profiles. Before changing the enabled state, the lifecycle helper makes a
mode-`0600` backup at `mailcow.conf.mcp.bak`; keep this file with the same care
as `mailcow.conf`.

Back up `mailcow.conf` before upgrades and include the MCP MariaDB schema in
the normal durable database backup. Those are the durable MCP recovery inputs.
The attachment volume contains only staged uploads, so backing it up is
optional; staged uploads may be lost during backup or recovery and must be
uploaded again.

## Lifecycle commands

Run the following from the mailcow checkout as root (or with the privilege
method your installation normally uses):

```bash
./helper-scripts/mcp.sh status
./helper-scripts/mcp.sh enable
./helper-scripts/mcp.sh disable
./helper-scripts/mcp.sh retry
```

`status` validates the MCP configuration and reports whether the exact `mcp`
profile token is enabled or disabled. It is not a live health or service-state
probe.
`enable` validates the configuration, records a backup, adds only the `mcp`
profile token, pulls the pinned `ghcr.io/mhupfauer/mcp:0.1.0` image, initializes
the dedicated database, starts the service, and verifies its public metadata.
If activation fails, it restores the previous profile configuration and nginx
state so the regular mailcow services remain independent.

`disable` removes only the `mcp` token, stops the long-running `mcp-mailcow`
application, and recreates nginx without MCP routes. It preserves the
initializer, MCP database, attachment volume, generated secrets, and OAuth
state; re-enabling is therefore reversible. `retry` is the focused recovery
command after an MCP activation or update failure.

### Readiness verification behind a load balancer

The activation check uses the public Mailcow HTTPS address by default. If the
Mailcow host cannot hairpin through its load balancer, set this in
`mailcow.conf` before running `enable` or `retry`:

```dotenv
MCP_ACTIVATION_LOCAL_VERIFY=1
```

In this mode the helper keeps the public hostname and MCP URLs but connects to
`127.0.0.1:${HTTPS_PORT:-443}` and accepts the local Mailcow certificate. This
checks local nginx routing and the MCP discovery/authentication contract; it
does not validate load-balancer health or public certificate trust. MCP client
traffic still uses the public endpoint.

## Destructive cleanup

Use purge only when MCP is disabled and permanent removal is intended:

```bash
./helper-scripts/mcp.sh purge
```

Purge asks for explicit destructive confirmation before removing the dedicated
MCP database and attachment volume. It does not remove mailbox data. Ordinary
mailcow updates and `disable` never run purge, so they preserve MCP data and
credentials.

## Image release

The release workflow publishes when a Git tag matching `mcp-v*` is pushed; the
version is taken from the tag, so `mcp-v0.1.0` publishes
`ghcr.io/<repository-owner>/mcp:0.1.0` for `linux/amd64` with provenance and an
SBOM. On this fork that resolves to `ghcr.io/mhupfauer/mcp:0.1.0`, matching the
pin in `docker-compose.yml`.

The MCP image is also built and pushed by the regular image build workflow on
every push to `master`, `staging`, and `feature/**`, alongside the other mailcow
images. Packages created by `GITHUB_TOKEN` are private by default, so a host
pulling them needs registry credentials unless the package is made public.
