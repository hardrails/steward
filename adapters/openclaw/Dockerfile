ARG OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw:2026.7.1@sha256:6a31d44b2944e7adcd2b582bf6fb463111264ebca97a0201795b799135bd102c
FROM ${OPENCLAW_IMAGE}

ARG OPENCLAW_SOURCE_REVISION=2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4
LABEL io.hardrails.steward.openclaw.source-revision=${OPENCLAW_SOURCE_REVISION} \
      io.hardrails.steward.openclaw.adapter-contract=steward.openclaw.v1

USER root

COPY --chown=0:0 --chmod=0555 entrypoint.mjs /opt/steward/entrypoint.mjs
COPY --chown=0:0 --chmod=0444 result.mjs /opt/steward/result.mjs
COPY --chown=0:0 --chmod=0555 fixture_model.mjs /opt/steward/fixture_model.mjs
COPY --chown=0:0 --chmod=0444 fixtures/skill/SKILL.md /opt/steward/skills/steward-workspace-audit/SKILL.md
COPY --chown=0:0 --chmod=0555 fixtures/skill/workspace_audit.mjs /opt/steward/skills/steward-workspace-audit/workspace_audit.mjs
COPY --chown=0:0 --chmod=0444 fixtures/workspace/qualification/input/alpha.txt /opt/steward/qualification/input/alpha.txt
COPY --chown=0:0 --chmod=0444 fixtures/workspace/qualification/input/nested.json /opt/steward/qualification/input/nested.json

# An empty Docker volume copies ownership and the qualification fixture from this
# directory. The adapter then verifies and publishes its exact skill files before
# starting OpenClaw as the same non-root identity Steward enforces.
RUN install -d -m 0700 -o 65532 -g 65532 \
      /home/node/.openclaw \
      /home/node/.openclaw/workspace \
      /home/node/.openclaw/workspace/qualification \
      /home/node/.openclaw/workspace/qualification/input && \
    chmod 0555 \
      /opt/steward/skills \
      /opt/steward/skills/steward-workspace-audit \
      /opt/steward/qualification \
      /opt/steward/qualification/input && \
    install -m 0444 -o 65532 -g 65532 \
      /opt/steward/qualification/input/alpha.txt \
      /home/node/.openclaw/workspace/qualification/input/alpha.txt && \
    install -m 0444 -o 65532 -g 65532 \
      /opt/steward/qualification/input/nested.json \
      /home/node/.openclaw/workspace/qualification/input/nested.json

ENV HOME=/home/node \
    TMPDIR=/tmp \
    OPENCLAW_STATE_DIR=/home/node/.openclaw \
    OPENCLAW_CONFIG_PATH=/tmp/steward-openclaw.json \
    OPENCLAW_DISABLE_BONJOUR=1 \
    NO_COLOR=1

USER 65532:65532
WORKDIR /home/node/.openclaw/workspace
ENTRYPOINT ["tini", "-s", "--", "node", "/opt/steward/entrypoint.mjs"]
CMD ["serve"]
