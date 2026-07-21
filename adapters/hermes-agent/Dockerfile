ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.6-python3.13-trixie@sha256:b3c543b6c4f23a5f2df22866bd7857e5d304b67a564f4feab6ac22044dde719b
FROM ${UV_IMAGE}

ARG HERMES_SOURCE_REVISION
LABEL io.hardrails.steward.hermes.source-revision=${HERMES_SOURCE_REVISION}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HERMES_HOME=/opt/data \
    HERMES_WRITE_SAFE_ROOT=/opt/data \
    HERMES_DISABLE_LAZY_INSTALLS=1 \
    HOME=/opt/data/home \
    TMPDIR=/tmp \
    PATH=/opt/hermes/.venv/bin:/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/hermes
COPY --chown=0:0 artifact/venv/.venv /opt/hermes/.venv
COPY --chown=65532:65532 artifact/state/ /opt/data/
COPY --chown=0:0 --chmod=0444 artifact/install_method /opt/hermes/.install_method
COPY --chown=0:0 --chmod=0444 upstream/LICENSE /usr/share/licenses/hermes-agent/LICENSE

COPY --chmod=0555 adapter/entrypoint.py /opt/steward/entrypoint.py
COPY --chmod=0555 adapter/fixture_model.py /opt/steward/fixture_model.py
COPY --chmod=0555 adapter/fixture_mcp.py /opt/steward/fixture_mcp.py
COPY --chown=0:0 --chmod=0555 adapter/fixtures/skill/workspace_audit.py /opt/steward/skills/steward.workspace-audit/workspace_audit.py
COPY --chown=0:0 --chmod=0444 adapter/fixtures/skill/SKILL.md /opt/steward/skills/steward.workspace-audit/SKILL.md
COPY --chown=0:0 --chmod=0444 adapter/fixtures/skill/workspace-fixture-contract.json /opt/steward/skills/steward.workspace-audit/workspace-fixture-contract.json
COPY --chown=0:0 --chmod=0444 adapter/fixtures/skill/manifest.json /opt/steward/skills/steward.workspace-audit/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/fixtures/skill/manifest.sig /opt/steward/skills/steward.workspace-audit/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/fixtures/skill/public.pem /opt/steward/skills/steward.workspace-audit/public.pem
COPY --chown=0:0 --chmod=0555 adapter/fixtures/connector-skill/connector_work.py /opt/steward/skills/steward.connector-work/connector_work.py
COPY --chown=0:0 --chmod=0444 adapter/fixtures/connector-skill/SKILL.md /opt/steward/skills/steward.connector-work/SKILL.md
COPY --chown=0:0 --chmod=0444 adapter/fixtures/connector-skill/connector-fixture-contract.json /opt/steward/skills/steward.connector-work/connector-fixture-contract.json
COPY --chown=0:0 --chmod=0444 adapter/fixtures/connector-skill/manifest.json /opt/steward/skills/steward.connector-work/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/fixtures/connector-skill/manifest.sig /opt/steward/skills/steward.connector-work/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/fixtures/connector-skill/public.pem /opt/steward/skills/steward.connector-work/public.pem
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/SKILL.md /opt/steward/profiles/research/SKILL.md
COPY --chown=0:0 --chmod=0555 adapter/profiles/research/research.py /opt/steward/profiles/research/research.py
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/manifest.json /opt/steward/profiles/research/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/manifest.sig /opt/steward/profiles/research/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/public.pem /opt/steward/profiles/research/public.pem
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/SKILL.md /opt/steward/profiles/developer/SKILL.md
COPY --chown=0:0 --chmod=0555 adapter/profiles/developer/coding_worker.py /opt/steward/profiles/developer/coding_worker.py
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/manifest.json /opt/steward/profiles/developer/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/manifest.sig /opt/steward/profiles/developer/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/public.pem /opt/steward/profiles/developer/public.pem

USER 65532:65532
WORKDIR /opt/data
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/steward/entrypoint.py"]
CMD ["serve"]
