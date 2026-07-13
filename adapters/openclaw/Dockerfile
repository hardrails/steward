# syntax=docker/dockerfile:1.7
ARG OPENCLAW_UPSTREAM_IMAGE
FROM ${OPENCLAW_UPSTREAM_IMAGE}

ARG OPENCLAW_SOURCE_REVISION
RUN test "$OPENCLAW_SOURCE_REVISION" = "7197eef3ebeb5ac294da51ca073fff33277ed429"

USER root
COPY --chmod=0555 adapters/openclaw/entrypoint.mjs /opt/steward/entrypoint.mjs
COPY --chmod=0555 adapters/openclaw/probe.mjs /opt/steward/probe.mjs
COPY --chmod=0555 adapters/openclaw/fixture-model.mjs /opt/steward/fixture-model.mjs
COPY --chmod=0555 adapters/openclaw/fixture-echo-mcp.mjs /opt/steward/fixture-echo-mcp.mjs
COPY --chmod=0555 adapters/openclaw/fixtures/fixture-sha256.mjs /opt/steward/fixtures/fixture-sha256.mjs
COPY --chmod=0444 adapters/openclaw/fixtures/SKILL.md /opt/steward/fixtures/SKILL.md
COPY --chmod=0444 adapters/openclaw/adapter.json /opt/steward/adapter.json
COPY --chmod=0444 adapters/openclaw/source-inputs.sha256 /opt/steward/source-inputs.sha256
RUN install -d -m 0700 -o 65532 -g 65532 /home/node/.openclaw /home/node/.openclaw/workspace && \
    install -d -m 0755 -o root -g root /opt/steward/fixtures && \
    chmod -R go-w /opt/steward

ENV HOME=/home/node \
    OPENCLAW_STATE_DIR=/home/node/.openclaw \
    NODE_ENV=production
USER 65532:65532
WORKDIR /home/node/.openclaw/workspace
ENTRYPOINT ["tini", "-s", "--", "node", "/opt/steward/entrypoint.mjs"]
