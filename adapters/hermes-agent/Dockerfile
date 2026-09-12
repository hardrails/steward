ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.12-python3.13-trixie-slim@sha256:2ab87c099cd28eeacc2d1122e8e2e020651fdf92c68d277caa003c3bba0627cc
FROM ${UV_IMAGE}

# Debian security updates absent from the pinned upstream base. Docker verifies
# the reviewed hashes before dpkg runs offline, before any Hermes source exists.
ADD --checksum=sha256:74cf12212beee4ab8d473bdc0107abf9e8cef737492198e2f4944a19f142b0ac https://deb.debian.org/debian/pool/main/g/gzip/gzip_1.13-1+deb13u1_amd64.deb /tmp/steward-gzip.deb
ADD --checksum=sha256:1252b96a5bc44bb5db982bef8eb18e54f5047cede2aff641bce4f8e1edb91c3e https://deb.debian.org/debian/pool/main/p/pcre2/libpcre2-8-0_10.46-1~deb13u2_amd64.deb /tmp/steward-pcre2.deb
ADD --checksum=sha256:0a459adaffd901109f7811ab65f58e7a957b4907d05539cf3d1184efdcde0468 https://deb.debian.org/debian/pool/main/s/sqlite3/libsqlite3-0_3.46.1-7+deb13u2_amd64.deb /tmp/steward-sqlite3.deb
ADD --checksum=sha256:b795464137a0f4d443fc9284f4b93e883fb83883cb533adf300ac660807a352a https://deb.debian.org/debian/pool/main/p/perl/perl-base_5.40.1-6+deb13u1_amd64.deb /tmp/steward-perl.deb
RUN ["dpkg", "--install", "/tmp/steward-gzip.deb", "/tmp/steward-pcre2.deb", "/tmp/steward-sqlite3.deb", "/tmp/steward-perl.deb"]
RUN ["rm", "/tmp/steward-gzip.deb", "/tmp/steward-pcre2.deb", "/tmp/steward-sqlite3.deb", "/tmp/steward-perl.deb"]

# Remove the unused base-image installer and its vendored dependencies. This
# fixed offline removal never executes Hermes source or dependency build hooks.
RUN ["/usr/local/bin/python3", "-I", "-m", "pip", "uninstall", "--yes", "pip"]

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
COPY --chown=0:0 upstream/ /opt/hermes/
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
COPY --chown=0:0 --chmod=0555 adapter/profiles/research/research.py /opt/steward/profiles/research/research.py
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/SKILL.md /opt/steward/profiles/research/SKILL.md
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/manifest.json /opt/steward/profiles/research/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/manifest.sig /opt/steward/profiles/research/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/profiles/research/public.pem /opt/steward/profiles/research/public.pem
COPY --chown=0:0 --chmod=0555 adapter/profiles/developer/coding_worker.py /opt/steward/profiles/developer/coding_worker.py
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/SKILL.md /opt/steward/profiles/developer/SKILL.md
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/manifest.json /opt/steward/profiles/developer/manifest.json
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/manifest.sig /opt/steward/profiles/developer/manifest.sig
COPY --chown=0:0 --chmod=0444 adapter/profiles/developer/public.pem /opt/steward/profiles/developer/public.pem

USER 65532:65532
WORKDIR /opt/data
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/steward/entrypoint.py"]
CMD ["serve"]
