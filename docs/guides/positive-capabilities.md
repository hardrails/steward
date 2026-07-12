---
title: Configure state, inference, and service grants
description: Enable Steward v1.4 persistent state, credential-hidden OpenAI-compatible inference, and authenticated private service ingress.
section: How-to
---

# Configure state, inference, and service grants

Steward v1.4 turns agent necessities into narrow grants instead of ambient
container privilege:

- state is one Executor-derived Docker volume, fixed at `/state`, keyed by tenant
  and lineage;
- inference is one site-policy-approved route through `steward-gateway`; the
  upstream bearer credential never enters the agent container; and
- service is one capsule-declared port reached through an authenticated loopback
  gateway path, not a raw agent container port.

Signed HTTP(S) egress is a separate named-route capability. There is still no raw
TCP/UDP, open/default-allow network, host bind mount, caller-selected environment,
or Docker socket access. See [Configure signed egress]({{ '/guides/egress/' | relative_url }}).

## 1. Configure the local model route

The package installs `/etc/steward/gateway.json` with a `local-openai` example
pointing to `http://127.0.0.1:11434/v1`. Replace that exact origin if your
OpenAI-compatible gateway listens elsewhere. If it requires a bearer token,
create an owner-only file:

```bash
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  ./local-model.token /etc/steward/local-model.token
```

Then add `"credential_file": "/etc/steward/local-model.token"` to the route.
Route IDs, URLs, and credentials are operator configuration, never tenant input.

## 2. Build the trusted relay without a registry

The installer/configurator does this automatically on a fresh node. To rebuild or
replace it deliberately, use the shipped relay binary to build a scratch image and write
its immutable Docker image ID into Executor's root-owned optional configuration:

```bash
sudo /usr/local/libexec/steward/build-relay-image --configure
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl restart steward-gateway steward-executor
```

The build uses no base image and `--network=none`. Executor accepts the resulting
content-addressed `sha256:…` image ID or a registry `name@sha256:…` reference.
It refuses a mutable tag.

The untrusted agent always runs under gVisor. The digest-pinned trusted relay runs
as a hardened `runc` container because gVisor intentionally denies host Unix-socket
access by default; enabling that broad escape hatch would be weaker than keeping
the relay tiny, fixed-destination, capability-free, read-only, and unexposed.

## 3. Authorize finite capabilities

The publisher capsule sets maximum booleans and declares the fixed state/service
shape. Site policy allowlists inference route IDs and service IDs per tenant.
The authenticated instance intent selects a subset and supplies:

- `state_disposition`: `new`, `resume`, or `none`;
- `inference_route_id` plus a bounded `model_alias`; and
- a `service_id` that exactly matches the capsule's declared service.

On admission, Executor returns `grant_id` and, for service grants,
`service_path`. The workload is created stopped. `start` brings up the trusted
relay, activates the gateway grant, and then starts the agent; `stop` closes the
grant before stopping the agent and relay.

## 4. Reach an agent service

The service gateway binds only to `127.0.0.1:8091` by default. A trusted local
caller uses the owner-provisioned gateway service token:

```bash
curl -H "Authorization: Bearer $(sudo cat /etc/steward/gateway-service-token)" \
  http://127.0.0.1:8091/v1/services/GRANT_ID/health
```

For remote users, place your own authenticated reverse proxy or private access
layer in front of that loopback endpoint. Steward's bearer credential authorizes
host service access; it is not tenant end-user identity.

## State lifecycle

Destroy retains the lineage volume so a higher generation can request `resume`.
`new` refuses an existing lineage and `resume` refuses a missing one. Permanent
removal requires `stewardctl node purge-state` or `steward_purge_state`, an
inactive signed tombstone, matching tenant/node/generation, a journaled Docker
removal, and a signed purge receipt.

## Air-gapped operation

All components work without Internet access after the Docker/gVisor host, agent
images, local inference service, signed artifacts, and release bundle have been
imported. The gateway never uses proxy environment variables, and the relay image
can be built entirely from the shipped static binary.
