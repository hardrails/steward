# syntax=docker/dockerfile:1.7
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.6-python3.13-trixie@sha256:b3c543b6c4f23a5f2df22866bd7857e5d304b67a564f4feab6ac22044dde719b
FROM ${UV_IMAGE} AS build

ARG HERMES_SOURCE_REVISION
RUN test "$HERMES_SOURCE_REVISION" = "095b9eed3801c251796df93f48a8f2a527ff6e70"

WORKDIR /opt/hermes
COPY upstream/ /opt/hermes/
COPY adapter/source-inputs.sha256 /tmp/source-inputs.sha256
RUN sha256sum -c /tmp/source-inputs.sha256 && \
    uv sync --frozen --no-install-project --extra mcp --extra homeassistant && \
    uv pip install --no-cache-dir --no-deps . && \
    rm -f /tmp/source-inputs.sha256

FROM ${UV_IMAGE}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HERMES_HOME=/opt/data \
    HERMES_WRITE_SAFE_ROOT=/opt/data \
    HERMES_DISABLE_LAZY_INSTALLS=1 \
    HOME=/opt/data/home \
    TMPDIR=/tmp \
    PATH=/opt/hermes/.venv/bin:/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/hermes
COPY --from=build /opt/hermes/.venv /opt/hermes/.venv
COPY --from=build --chmod=0444 /opt/hermes/LICENSE /usr/share/licenses/hermes-agent/LICENSE

COPY --chmod=0555 adapter/entrypoint.py /opt/steward/entrypoint.py
COPY --chmod=0555 adapter/fixture_model.py /opt/steward/fixture_model.py
COPY --chmod=0555 adapter/fixture_mcp.py /opt/steward/fixture_mcp.py
COPY --chmod=0555 adapter/fixtures/skill/workspace_audit.py /opt/steward/fixtures/skill/workspace_audit.py
COPY --chmod=0444 adapter/fixtures/skill/SKILL.md /opt/steward/fixtures/skill/SKILL.md
COPY --chmod=0444 adapter/fixtures/skill/workspace-fixture-contract.json /opt/steward/fixtures/skill/workspace-fixture-contract.json
COPY --chmod=0444 adapter/fixtures/skill/manifest.json /opt/steward/fixtures/skill/manifest.json
COPY --chmod=0444 adapter/fixtures/skill/manifest.sig /opt/steward/fixtures/skill/manifest.sig
COPY --chmod=0444 adapter/fixtures/skill/public.pem /opt/steward/fixtures/skill/public.pem

RUN mkdir -p /opt/data /opt/data/home /tmp && \
    printf 'docker\n' > /opt/hermes/.install_method && \
    chown -R 65532:65532 /opt/data && \
    chmod 0700 /opt/data /opt/data/home && \
    chmod -R go-w /opt/steward /opt/hermes

USER 65532:65532
WORKDIR /opt/data
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/steward/entrypoint.py"]
CMD ["serve"]
