---
title: OpenClaw on Steward
description: Build and admit a digest-pinned OpenClaw profile with persistent state, brokered local inference, and one private gateway service.
section: Agent compatibility
---

# OpenClaw on Steward

Steward v1.3 has a built-in `openclaw-v1@v1` layout. It mounts the lineage volume
at `/home/node/.openclaw`, sets `HOME=/home/node`, and can grant one declared
OpenClaw service port plus one brokered OpenAI-compatible model route.

OpenClaw changes quickly. Review its current
[Docker guide](https://github.com/openclaw/openclaw/blob/main/docs/install/docker.md),
pin an exact source release and base-image digest, and verify the CLI command and
gateway port for that release before signing a capsule.

## Prepare a compatible immutable image

The approved image must run as UID/GID `65532`, contain every required runtime
dependency, and pre-create writable state/workspace directories. A derivative has
this shape; adapt the entrypoint only after checking the pinned source:

```dockerfile
FROM ghcr.io/openclaw/openclaw@sha256:REPLACE_WITH_REVIEWED_DIGEST
USER root
RUN mkdir -p /home/node/.openclaw/workspace \
 && chown -R 65532:65532 /home/node
USER 65532:65532
ENV HOME=/home/node
ENTRYPOINT ["node", "dist/index.js"]
```

Build and scan it in a trusted pipeline. Import the digest-pinned image into the
node; Steward never pulls it during admission.

## Author the capsule and intent

Use profile `openclaw-v1@v1` and state path `/home/node/.openclaw`. First sign an
offline `--help` command. For a connected gateway, set the capsule's fixed service
ID and exact port to those used by the pinned release, then allow that service ID
and inference route in site policy.

A connected intent requests state, inference, and service, supplies
`state_disposition`, `inference_route_id`, `model_alias`, and the exact
`service_id`. Admission returns a `grant_id` and `service_path`; start activates
the relay and gateway before starting OpenClaw.

OpenClaw may require provider settings in `openclaw.json` rather than relying only
on standard OpenAI environment variables. Seed an approved configuration in the
image's state directory that points to `http://steward-relay:8080/v1` and uses a
non-secret placeholder key. Never bake the real upstream credential into the image.

Reach the declared service through the authenticated loopback endpoint described
in [positive-capability setup]({{ '/guides/positive-capabilities/' | relative_url }}).

## Deliberate limits

Messaging channels, plugin downloads, browser control, arbitrary web access,
Docker-based nested sandboxes, extra mounts, mDNS, and undeclared ports are not
provided by the state/inference/service grants. OpenClaw can be useful with a local
model and private gateway while those broader capabilities remain denied.
