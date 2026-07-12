---
title: OpenClaw adapter contract
description: Understand the built-in OpenClaw layout, its upstream runtime and onboarding requirements, Steward's bounded WebSocket service path, and the acceptance work required for a hardened adapter.
section: Agent compatibility
---

# OpenClaw adapter contract

The compiled-in `openclaw-v1@v1` **layout contract** fixes paths and identity
settings that an untrusted capsule cannot change. Steward does not include OpenClaw,
build its image, or certify the upstream image.

| Property | Enforced value |
| --- | --- |
| persistent state | `/home/node/.openclaw` |
| `HOME` | `/home/node` |
| working directory | `/home/node/.openclaw/workspace` |
| process identity | UID/GID `65532:65532` |
| writable filesystem | lineage volume plus a 64 MiB memory-backed `/tmp` (`tmpfs`) |

A lineage volume preserves one workload's state across approved replacements.
Steward's portable Docker volume has no hard byte or inode quota, so this layout is
usable only with the explicit dedicated-host state mode. It is not a shared-host
state guarantee.

OpenClaw changes quickly. The status below was reviewed on 2026-07-11 at upstream
commit
[`7197eef3ebeb5ac294da51ca073fff33277ed429`](https://github.com/openclaw/openclaw/commit/7197eef3ebeb5ac294da51ca073fff33277ed429),
using its pinned
[Docker guide](https://github.com/openclaw/openclaw/blob/7197eef3ebeb5ac294da51ca073fff33277ed429/docs/install/docker.md),
[Dockerfile](https://github.com/openclaw/openclaw/blob/7197eef3ebeb5ac294da51ca073fff33277ed429/Dockerfile),
[gateway runbook](https://github.com/openclaw/openclaw/blob/7197eef3ebeb5ac294da51ca073fff33277ed429/docs/gateway/index.md),
and [Gateway protocol](https://github.com/openclaw/openclaw/blob/7197eef3ebeb5ac294da51ca073fff33277ed429/docs/gateway/protocol.md).
Review the exact revision you plan to package; a later upstream change can
invalidate this assessment.

## Current validation status

Steward does not ship or claim a validated OpenClaw adapter. The built-in layout is
enforcement metadata; it does not mean the official image passed end-to-end tests.

The official container runs as `node` with UID `1000`. It keeps state and
`openclaw.json` under `/home/node/.openclaw`, but stores the auth-profile encryption
key under `/home/node/.config/openclaw`. Docker onboarding creates configuration and
authentication material before Gateway startup. Steward enforces UID/GID
`65532:65532`, mounts only the declared state path, permits no interactive exec, and
provides no generic secret or extra-mount channel.

The upstream Gateway multiplexes HTTP and WebSocket traffic on port `18789`, fitting
Steward's one-port contract. UID, state initialization, the separate key path, and
two-layer authentication still require an adapter and tests. Do not hide these gaps
by baking provider keys, channel tokens, OAuth material, or a reusable Gateway token
into the image.

## What Steward's service path provides

For an active grant, a trusted host-local caller authenticates to Gateway and reaches
the capsule-declared port through the relay. Steward preserves path and query and
supports HTTP/1.1 RFC 6455 WebSocket upgrades. Limits are:

- at most 16 concurrent HTTP requests or WebSocket streams per grant;
- a two-minute lifetime for each request or stream;
- at most 4 MiB from client to service and 32 MiB from service to client; and
- immediate connection cancellation when the grant is deactivated or removed.

Steward consumes the outer `Authorization` header. It does not forward client
`Authorization`, `Proxy-Authorization`, `Cookie`, or upstream `Set-Cookie` headers.
OpenClaw authentication must occur inside the WebSocket `connect` frame; Steward's
bearer token is not an OpenClaw token. These transport properties are tested, but a
complete Control UI and protocol session has not passed the requirements below.

## Adapter acceptance contract

A signed OpenClaw adapter must satisfy all of the following:

1. Pin the source revision and every base image by digest. Record source, inputs,
   output manifest and config digests, and platform.
2. Make the image start and remain at UID/GID `65532:65532`. Pre-create only
   the required state/workspace paths, prove all runtime writes stay under
   `/home/node/.openclaw` or `/tmp`, and prove the image works read-only with
   all capabilities dropped and `no-new-privileges`.
3. Produce deterministic offline first-run configuration without secrets in the
   image, archive, capsule, arguments, or logs. Resolve the auth-profile key path:
   prove the approved configuration does not use it, or propose a
   reviewed profile change. Never silently move or discard it.
4. Configure a custom OpenAI-compatible provider from Steward's injected
   `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `OPENAI_MODEL`. `OPENAI_API_KEY` is
   the fixed, non-secret placeholder `steward-local`; Gateway removes the agent's
   `Authorization` header and injects the operator-owned upstream credential, if
   configured. Prove OpenClaw requests only the signed model alias and cannot
   enumerate or select another upstream model.
5. Bind the OpenClaw Gateway to the adapter's private interface on the single
   capsule-declared port. Preserve upstream's single-port HTTP/WebSocket
   multiplexing; do not publish a Docker port or add a second listener.
6. Design OpenClaw Gateway authentication without reusing Steward's service token.
   Prove an authorized client can complete `connect.challenge` and authenticated
   `connect` through Steward while an unauthorized client cannot. This remains
   blocking; the current profile does not inject an OpenClaw Gateway secret.
7. Test HTTP health and a real WebSocket remote procedure call (RPC) session through
   `service_path`. Test
   concurrency, byte, lifetime, and revocation limits, restart reconciliation, and
   retained state.
8. Disable or reject features that require multicast DNS (mDNS/Bonjour), raw
   messaging
   transports, browser control, a Docker socket, nested Docker sandboxes, host
   mounts, extra ports, or arbitrary environment variables. For an HTTP(S) channel
   or plugin, verify that its exact library honors the injected proxy and authorize
   only its named route. A protocol name alone does not prove compatibility.
9. Sign only the tested argument vector and service port. Store resulting receipts
   with source and image identities.

This checklist is a release gate. It is not evidence that a compliant adapter
already exists.

## Inspect and import an adapter immutably

Inspect a trusted-pipeline archive before it reaches Docker:

```console
chmod go-w openclaw-adapter.tar
stewardctl image inspect -archive openclaw-adapter.tar
```

Take the manifest digest, config digest, and platform from `image inspect`. Select
the approved repository provenance separately from the trusted build or promotion
pipeline; an OCI archive may not contain a repository name. Sign those values and
the `openclaw-v1@v1` profile into a capsule. After site policy authorizes them,
import the same bytes:

```console
sudo stewardctl image import \
  -archive openclaw-adapter.tar \
  -capsule openclaw-capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

Import success proves archive identity and the static image contract, not OpenClaw
runtime compatibility. See
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}) and
[signed admission]({{ '/guides/signed-admission/' | relative_url }}).

## Deliberate capability limits

Steward does not provide OpenClaw discovery, multicast DNS (mDNS), raw messaging
protocols, browser control, Docker-based sandboxes, host projects, arbitrary
credentials, extra mounts, or undeclared ports. You may qualify a proxy-aware
HTTP(S) integration against an exact signed egress route. Another OpenClaw
deployment reaching it does not prove Steward compatibility.
