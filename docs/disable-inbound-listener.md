---
title: Disabling the inbound listener
description: Why and how an uplink-only Steward node can run without binding an inbound management socket.
section: Design record
---

# Disabling the inbound listener

Status: **implemented.** This is a deployment setting in `cmd/steward`. It changes
which network sockets the process opens; it does not change a handler, tracker
operation, API shape, or status code. `openapi/steward.v1.yaml` therefore remains
unchanged.

## Why this exists

Steward has two independent control paths:

- The inbound REST API accepts connections on `-addr`, which defaults to
  `127.0.0.1:8080`.
- The outbound uplink connects to a control plane, polls for commands, and calls the
  tracker directly in-process.

An uplink is useful when network address translation (NAT) or a firewall prevents
the control plane from connecting to the node. In that deployment, an inbound
listener is not required for fleet operations. Keeping it open adds a socket to
audit and protect, even when it is bound only to loopback.

`-disable-inbound-listener` lets an uplink-only node bind no inbound HTTP socket.
The uplink continues to work because it does not call the local REST API. Both paths
are callers of the same mutex-protected `internal/runtime.Tracker`; neither depends
on the other.

## Contract

The setting is:

```
-disable-inbound-listener   STEWARD_DISABLE_INBOUND_LISTENER   (default false)
    do not bind an inbound HTTP listener; requires -uplink-url. All fleet
    operations then flow through the outbound uplink poll loop only.
```

The environment value is parsed as a strict boolean. An invalid value stops startup
instead of silently changing whether the node accepts inbound HTTP connections.

| `-disable-inbound-listener` | `-uplink-url` | Result |
| --- | --- | --- |
| unset | unset | The listener binds `-addr`; no uplink runs. |
| unset | set | The listener and uplink both run. |
| set | unset | Startup fails because the node would have no control path. |
| set | set | No inbound listener is created; the uplink is the only control path. |

When the listener is disabled:

- Steward does not create an `http.Server` or call `ListenAndServe`.
- `-addr` is unused and is not validated by `-check-config` because nothing will
  bind it.
- Startup logs `inbound listener disabled; serving via uplink only` instead of
  `steward listening`.
- Shutdown still cancels and waits for the uplink. The server shutdown call is
  skipped because no server exists.

The setting is read once at startup. Changing between listener and uplink-only modes
requires a restart.

## Health, readiness, and metrics

Disabling the listener also removes every endpoint served by it, including:

- `GET /v1/healthz`
- `GET /v1/readiness`
- `GET /v1/capabilities`
- `GET /metrics`, even when `-enable-metrics` is set

A service manager such as systemd can still determine whether the process is alive
and can act on exit status and error logs. Poll failures, credential rejection, and
credential recovery are logged. A quiet successful poll is not logged on every
cycle, however, so process liveness alone is not positive proof that the control
plane remains reachable.

Leave the listener enabled on loopback when a local HTTP health check, readiness
check, capabilities query, or metrics scrape is required. Disabling it is an
explicit tradeoff: the node has no inbound socket and no local HTTP endpoints for
health, readiness, capabilities, or metrics.

## Safety properties

- **Listener-on remains the default.** Existing deployments keep the REST API unless
  the operator explicitly disables it.
- **At least one control path is required.** Disabling the listener without
  `-uplink-url` stops startup with an error that names both remedies.
- **The uplink stays independent.** `internal/uplink` uses its own outbound
  `http.Client` and calls tracker methods directly. Removing the listener does not
  reroute or weaken uplink command handling.
- **No dependency is added.** The implementation uses `flag.Bool`, strict standard-
  library boolean parsing, and a conditional server startup path.

This setting removes an inbound socket; it does not by itself authenticate the
uplink. Uplink credentials and TLS settings remain separate security controls. See
[Outbound uplink client]({{ '/uplink-client/' | relative_url }}).

## Alternatives rejected

### Treat an empty `-addr` as disabled

This would overload a setting whose current meaning is “where to listen.” It also
would not work consistently through `STEWARD_ADDR`: `envOr` treats an empty
environment value as absent and restores the default address. A dedicated boolean
has the same meaning through flags, environment variables, and JSON configuration.

### Keep a health-only loopback listener

That would retain the socket this setting exists to remove and require a second
server configuration. Operators who need an HTTP probe can keep the normal loopback
listener.

### Allow neither listener nor uplink

The resulting process could not receive work. Steward treats that combination as a
configuration error instead of starting an unreachable node.

### Name the setting `-uplink-only`

That name would imply that the setting enables the uplink. It does not;
`-uplink-url` still enables the uplink. `-disable-inbound-listener` describes the
one action the flag performs.

## Implementation evidence

The behavior is covered by the following tests:

- `TestDisableInboundListenerWithoutUplinkExitsNonZero`
- `TestDisableInboundListenerMalformedEnvExitsNonZero`
- `TestDisableInboundListenerStartsCleanWithUplink`
- `TestDisableInboundListenerRecoversFromFatalPollRejectionViaCredentialHotReload`
- `TestListenerEnabledByDefault`
- `TestCheckConfigIgnoresAddrWhenInboundDisabled`
- `TestConfigSchemaDisableInboundRequiresUplink`

The shutdown integration test starts a listener-free process, waits for its startup
marker, sends `SIGTERM`, and requires a clean exit without a panic. The default-path
test confirms that omitting the flag still binds and logs `steward listening`.

## Not provided

Steward does not provide a separate Unix-socket health probe, readiness file, or
split fleet/health listeners for this mode. Those would create another interface to
secure and support. They should be added only for a demonstrated operator need.
