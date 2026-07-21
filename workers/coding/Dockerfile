FROM node:22-bookworm@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37

ARG TARGETARCH

ENV HOME=/home/worker \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/worker/node_modules/.bin:/usr/local/bin:/usr/bin:/bin

WORKDIR /opt/worker
COPY --chown=0:0 --chmod=0444 package.json package-lock.json ./
RUN case "$TARGETARCH" in \
      amd64) npm_arch=x64 ;; \
      arm64) npm_arch=arm64 ;; \
      *) echo "unsupported coding-worker architecture: $TARGETARCH" >&2; exit 2 ;; \
    esac && \
    npm_config_arch="$npm_arch" npm ci --omit=dev --ignore-scripts && \
    install -o 0 -g 0 -m 0555 "/opt/worker/node_modules/@anthropic-ai/claude-code-linux-$npm_arch/claude" /usr/local/bin/claude && \
    npm cache clean --force && \
    install -d -o 65532 -g 65532 -m 0700 /home/worker /home/worker/.codex /home/worker/.claude
COPY --chown=0:0 --chmod=0555 coding_worker.py /opt/worker/coding_worker.py

USER 65532:65532
WORKDIR /workspace
EXPOSE 8080
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/worker/coding_worker.py"]
