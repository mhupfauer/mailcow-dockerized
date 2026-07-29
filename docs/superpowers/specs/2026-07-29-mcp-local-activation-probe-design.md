# MCP Local Activation Probe Design

**Date:** 2026-07-29

## Problem

`helper-scripts/mcp.sh enable` verifies the MCP endpoints through the public
`https://${MAILCOW_HOSTNAME}` address before it commits the enabled state. This
fails when Mailcow is behind a load balancer that cannot be reached through
hairpin routing from the Mailcow host. It also fails when the local Mailcow
HTTPS listener presents its default self-signed certificate.

The activation check must be able to connect directly to the local Mailcow
HTTPS listener without changing the public URLs that the MCP server publishes
or validates.

## Configuration

Add the non-secret setting below to `mailcow.conf`:

```dotenv
MCP_ACTIVATION_LOCAL_VERIFY=0
```

The accepted values are `0` and `1`. Existing installations receive the
default value through the normal MCP configuration migration. An explicitly
configured value is preserved during updates.

The default remains `0`, which keeps the current strict public HTTPS
verification. Operators whose Mailcow instance is behind a load balancer set
the value to `1`.

This is one combined mode rather than separate insecure-TLS and connection
target settings. The narrower interface avoids unsupported combinations and
does not expose an arbitrary connection target in a root-operated helper.

## Activation Probe

The helper continues to construct all endpoint URLs from:

```text
https://${MAILCOW_HOSTNAME}
```

When `MCP_ACTIVATION_LOCAL_VERIFY=1`, every activation readiness request adds
the equivalent of:

```text
--insecure
--connect-to ${MAILCOW_HOSTNAME}:443:127.0.0.1:${HTTPS_PORT}
```

`HTTPS_PORT` comes from `mailcow.conf` and defaults to `443` if it is absent.
It must be an integer from 1 through 65535. The destination is fixed to
`127.0.0.1`; `localhost` is not used because its IPv4/IPv6 resolution varies
between systems.

`curl --connect-to` changes only the TCP destination. The request URL, HTTP
Host header, TLS server name, OAuth issuer, and protected-resource identity
remain the public Mailcow hostname. `--insecure` is limited to these activation
readiness requests and does not alter MCP runtime traffic or the public TLS
configuration.

The three existing checks remain unchanged in meaning:

1. Authorization-server metadata must return HTTP 200 and the exact public
   issuer.
2. Protected-resource metadata must return HTTP 200 and the exact public MCP
   resource and authorization-server reference.
3. `POST /mcp` without a token must return HTTP 401 and advertise the exact
   protected-resource metadata URL.

## Validation and Failure Behavior

The helper validates `MCP_ACTIVATION_LOCAL_VERIFY` before changing activation
state. In local verification mode it also validates `HTTPS_PORT` before making
requests. Invalid values fail with a clear error and leave MCP disabled.

Connection failures, malformed responses, and contract mismatches continue to
use the existing retry and rollback behavior. Enabling local verification does
not weaken the JSON field or authentication-challenge checks.

This mode proves that the local Mailcow HTTPS routing and MCP contracts work.
It deliberately does not prove that the load balancer is healthy or that the
public certificate is trusted. Operators remain responsible for valid public
TLS at the load balancer.

## Compatibility and Update Behavior

The setting is appended by the existing versioned MCP configuration migration,
so pre-existing Mailcow deployments do not require manual secret generation or
configuration reconstruction. The default preserves existing behavior.

No Compose service, container environment, database schema, or MCP protocol
change is required. The setting is consumed only by the lifecycle helper.

## Testing

Configuration tests will verify that:

- migrated configurations receive `MCP_ACTIVATION_LOCAL_VERIFY=0`;
- explicit existing values are preserved; and
- only `0` and `1` are accepted.

Lifecycle tests will verify that:

- default mode sends neither `--insecure` nor `--connect-to`;
- local mode adds both options to all three readiness requests;
- the connection mapping uses the public hostname, fixed IPv4 loopback, and
  configured HTTPS port while the request URLs remain public;
- invalid mode or port values fail before activation; and
- existing retry and rollback behavior remains intact.

## Non-Goals

This change does not add automatic load-balancer detection, arbitrary probe
targets, public certificate provisioning, or a general switch that disables
TLS verification for MCP clients.

The currently missing protected-resource metadata endpoint is also outside
this helper change. Until that endpoint is implemented, the second readiness
check will correctly continue to fail with HTTP 404.
