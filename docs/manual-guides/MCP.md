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

Back up `mailcow.conf` before upgrades and keep the normal mailcow backups.
MCP state uses its own MariaDB schema and attachment volume, so an MCP backup
and recovery plan should include both the database and that volume when MCP is
enabled.

## Lifecycle commands

Run the following from the mailcow checkout as root (or with the privilege
method your installation normally uses):

```bash
./helper-scripts/mcp.sh status
./helper-scripts/mcp.sh enable
./helper-scripts/mcp.sh disable
./helper-scripts/mcp.sh retry
```

`status` reports whether the profile is enabled and the service state.
`enable` validates the configuration, records a backup, adds only the `mcp`
profile token, pulls the pinned `ghcr.io/mailcow/mcp:0.1.0` image, initializes
the dedicated database, starts the service, and verifies its public metadata.
If activation fails, it restores the previous profile configuration and nginx
state so the regular mailcow services remain independent.

`disable` removes only the `mcp` token and stops the MCP-profile services. It
does not delete the MCP database, generated secrets, OAuth state, or attachment
volume; re-enabling is therefore reversible. `retry` is the focused recovery
command after an MCP activation or update failure.

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

The implementation workflow publishes only when the exact Git tag
`mcp-v0.1.0` is pushed. It is configured to build the pinned
`ghcr.io/mailcow/mcp:0.1.0` image for `linux/amd64` and `linux/arm64` with
provenance and an SBOM. Publishing that tag requires a maintainer with GHCR
write authority; until then, this document describes implementation behavior,
not an already-published image or deployed service.
