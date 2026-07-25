ARG BASE_IMAGE=steward-capability-base:local
FROM ${BASE_IMAGE}

COPY --chown=65532:65532 --chmod=0755 httpd /usr/local/bin/httpd
COPY --chown=65532:65532 state/ /state/

USER 65532:65532
ENTRYPOINT []
