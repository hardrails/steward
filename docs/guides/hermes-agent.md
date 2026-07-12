---
title: Hermes Agent on Steward
description: Build and admit a digest-pinned Hermes Agent profile with persistent /opt/data state and brokered OpenAI-compatible inference.
section: Agent compatibility
---

# Hermes Agent on Steward

Steward v1.4 has a built-in `hermes-v1@v1` layout: persistent state is mounted at
`/opt/data`, `HOME` is `/opt/data/home`, and OpenAI-compatible requests are routed
to the per-instance relay. This matches Hermes' documented state and custom-model
interfaces without exposing the real model credential to Hermes.

Hermes is independently developed. Pin an upstream release and review its current
[Docker guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/docker.md)
and [configuration reference](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/configuration.md)
before producing an approved capsule.

## Prepare a compatible immutable image

The official image normally starts an s6 root entrypoint that reconciles ownership.
Steward always runs the agent as UID/GID `65532`, so approve a small derivative
that pre-creates the state tree and starts Hermes directly:

```dockerfile
FROM nousresearch/hermes-agent@sha256:REPLACE_WITH_REVIEWED_DIGEST
USER root
RUN mkdir -p /opt/data/home && chown -R 65532:65532 /opt/data
USER 65532:65532
ENV HOME=/opt/data/home
ENTRYPOINT ["/opt/hermes/.venv/bin/hermes"]
```

Build this in your trusted image pipeline, scan it, push or export it, and use its
immutable repository digest plus Docker config digest in the signed capsule.
Tags are not admitted.

## Author the capsule and intent

Use profile `hermes-v1@v1`, state shape `{"schema_version":"v1","path":"/opt/data"}`,
and a command verified against the pinned release. Start with `--help`; for a
gateway deployment, the current upstream command is `gateway run`.

Set the capsule capability ceilings you have reviewed. A useful local-model intent
typically requests:

```json
{
  "capabilities": {"state": true, "inference": true, "service": false, "egress": false},
  "state_disposition": "new",
  "inference_route_id": "local-openai",
  "model_alias": "approved-model"
}
```

Hermes documents `OPENAI_BASE_URL` and `OPENAI_API_KEY` for custom compatible
endpoints. Steward injects a private relay base URL and a non-secret sentinel key;
the host gateway replaces that value with the configured upstream credential.

Admit and start with `stewardctl node` or the MCP tools. Destroy retains
`/opt/data`; a higher generation can request `resume`. See
[positive-capability setup]({{ '/guides/positive-capabilities/' | relative_url }}).

## Deliberate limits

Hermes skills can use standard HTTP(S) through explicitly named routes. Set capsule
and intent `egress` to true and select only the routes the skill needs; Steward
injects standard proxy variables automatically. See [signed egress]({{ '/guides/egress/' | relative_url }}).
Raw TCP/UDP, browser sandboxes, host projects, Docker, and unlisted messaging or API
destinations remain denied; do not enable general container networking as a workaround.
