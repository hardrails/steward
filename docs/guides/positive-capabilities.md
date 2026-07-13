---
title: Configure finite workload capabilities
description: Configure dedicated-host state, credential-hidden inference, private service ingress, exact authenticated operations, and bounded HTTP(S) egress.
section: How-to
---

# Configure finite workload capabilities

**Positive capabilities** are explicit grants for state or network access. They
replace unrestricted container privileges.

- state is one Steward-owned Docker volume at the profile's fixed path (`/state`
  for the generic profile), keyed by tenant and workload history. Docker's portable
  local volume driver has no hard byte or inode quota, so state is disabled by
  default and is not supported on shared multi-tenant hosts;
- inference is one site-policy-approved route and model alias through
  `steward-gateway`; Gateway does not configure, mount, or inject the upstream
  bearer credential into the agent container; and
- service is one capsule-declared port reached through an authenticated loopback
  gateway path, not a raw agent container port.

Signed HTTP(S) egress uses separate named routes. Steward provides no raw TCP/UDP,
default-allow network, host bind mount, caller-selected environment, or Docker socket.
See [Configure signed egress]({{ '/guides/egress/' | relative_url }}).

Authenticated API work uses named connectors. Gateway maps each logical operation
to an exact method, path, origin, credential, and call budget without placing the
origin or credential in the workload. A connector can also require a short-lived
tenant-scoped action permit that signs the exact request bytes. The signing key
stays off-node; Gateway spends the authorization and records the permit and request
digests before the effect. See
[Broker authenticated API operations]({{ '/guides/connectors/' | relative_url }}).

Gateway rejects the exact configured connector credential in upstream response
headers and the decoded body stream. It does not detect transformed credentials,
private-origin disclosure, or other application secrets, and it does not apply an
upstream-specific response schema. Treat each inference and connector upstream as a
trusted service and use narrow, tenant-specific credentials.

To use persistent state on a dedicated single-tenant host, set
`EXECUTOR_STATE_ARG=-allow-unquotaed-state-on-dedicated-host` in
`/etc/steward/executor.env`, then run preflight and restart Executor. The flag name
is deliberately explicit: a tenant can fill the backing filesystem because the
volume has no portable hard quota. Executor also requires complete signed admission
with a verified policy containing exactly one tenant. Do not enable it on a shared
host.

These networks require Docker Engine 28 or newer. Isolated bridge gateway mode lets
the agent reach its relay but not host services through the bridge gateway.
Preflight rejects older versions before network creation. A `network=none` workload
with no network capability can use an older supported Engine.

## 1. Configure the local model route

The `local-openai` example in `/etc/steward/gateway.json` points to
`http://127.0.0.1:11434/v1`. Change it for another OpenAI-compatible gateway. For a
bearer token, create an owner-only file:

```bash
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  ./local-model.token /etc/steward/local-model.token
```

Add `"credential_file": "/etc/steward/local-model.token"` to the route. Operators,
not tenants, configure route IDs, URLs, and credentials.

## 2. Build the trusted relay without a registry

After verifying signed admission, the installer builds and configures the relay.
Executor creates each isolated capability network later, when it admits a workload
that requests a network capability. Staged and unsigned local-only nodes do neither.
To replace the relay, build its scratch image and record the immutable ID in
root-owned Executor configuration:

```bash
sudo /usr/local/libexec/steward/build-relay-image --configure
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl restart steward-gateway steward-executor
```

The build uses no base image and `--network=none`. Executor accepts the resulting
content-addressed `sha256:…` image ID or a registry `name@sha256:…` reference.
It refuses a mutable tag.

The untrusted agent runs under gVisor. The pinned trusted relay uses hardened `runc`
because gVisor denies host Unix sockets by default. Broadening gVisor would be weaker
than a small, read-only relay with no Linux capabilities, fixed destinations, and no
exposed host port.

## 3. Authorize finite capabilities

The publisher capsule sets capability ceilings and fixed state/service shape. Site
policy lists each tenant's allowed inference routes, model aliases, and services:

```json
{
  "tenant_id": "tenant-a",
  "inference_route_ids": ["local-openai"],
  "inference_model_aliases": ["private-model"],
  "service_ids": ["agent-api"]
}
```

The authenticated instance intent selects a subset:

- `state_disposition`: `new`, `resume`, or `none`;
- a non-empty `inference_route_id` of at most 128 bytes plus a non-empty
  `model_alias` of at most 256 bytes with no NUL (zero) byte; and
- a `service_id` that exactly matches the capsule's declared service.

Executor returns `grant_id` and, for service, `service_path`. Inference, connector,
or egress also returns `route_policy_digest`, a deterministic non-secret digest of
retained route settings. Executor evidence records it, and Gateway rejects changes
while a retained grant uses the route.

Workloads are created stopped. `start` launches the relay, binds and verifies the
grant, starts the agent, then activates the grant. Activation comes last so an
active grant never points at a stopped agent. `stop` deactivates the grant before
stopping the agent and relay.

### Inference request boundary

Gateway allows only `POST /v1/chat/completions`, `/v1/completions`,
`/v1/embeddings`, and `/v1/responses`, plus `GET /v1/models`. Every POST body is
at most 4 MiB and must be one JSON object without duplicate top-level names. It must
contain exactly one string `model` equal to the signed `model_alias`; Gateway rejects
missing or different values before upstream. It generates `/v1/models` locally with
only that alias. The tenant rule must list the alias in `inference_model_aliases`.
A route credential that reaches other models does not grant access to them.
Inference responses are limited to 32 MiB. A known-length larger response returns
`502 response_too_large` before body forwarding. For an unknown-length response,
Gateway preserves streaming and advertises an `X-Steward-Stream-Status` trailer. A
clean response ends with `completed`. An upstream read failure or a byte beyond 32
MiB aborts the stream, so the client receives a framing or body-read error instead
of a valid-looking truncated response.

## 4. Reach an agent service

The service gateway binds only to `127.0.0.1:8091` by default. A trusted local
caller uses the owner-provisioned gateway service token:

```bash
curl -H "Authorization: Bearer $(sudo cat /etc/steward/gateway-service-token)" \
  http://127.0.0.1:8091/v1/services/GRANT_ID/health
```

Gateway dials the exact `s.sock` in this grant's host-owned socket directory. The
relay forwards that traffic only to the capsule-declared agent port. Docker does
not publish the agent or relay port, so isolated bridge mode does not require a
host-to-container IP route.

Remote users need an authenticated reverse proxy or private access layer. Steward's
bearer credential authorizes the host service, not a tenant end user.

HTTP and RFC 6455 WebSockets share one path. Gateway removes outer `Authorization`,
`Proxy-Authorization`, `Cookie`, and upstream `Set-Cookie` headers. Each grant allows
at most 16 concurrent requests or streams, a two-minute lifetime, 4 MiB
client-to-service, and 32 MiB service-to-client. Stop, destroy, deactivation, or
grant removal immediately cancels active traffic. The adapter must authenticate
within the agent service.

## State lifecycle

When the dedicated-host state mode is enabled, destroy retains the volume for one
workload history so a higher generation can request `resume`. `new` rejects an
existing lineage; `resume` rejects a missing one. Permanent removal requires
`stewardctl node purge-state` or `steward_purge_state`, an inactive signed tombstone,
matching tenant/node/generation, a journaled Docker removal, and a signed purge
receipt.

## Air-gapped operation

No public Internet access is required after Docker and gVisor are installed and the
agent images, local inference service, signed artifacts, and release bundle are on
site. Enabled uplinks and model routes must still reach their configured on-site
endpoints. Gateway never uses proxy environment variables. The shipped static
binary is enough to build the relay image.
