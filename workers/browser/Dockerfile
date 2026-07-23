FROM mcr.microsoft.com/playwright:v1.61.0-noble@sha256:57b65fdc9ceabe0ef613124c7bbe2babcf9362c4d85e382fe3b03604e84b428a

WORKDIR /opt/steward-browser
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force
COPY server.mjs security.mjs ./

ENV HOME=/tmp/steward-browser \
    NODE_ENV=production \
    STEWARD_BROWSER_LISTEN=0.0.0.0:8080
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["node", "/opt/steward-browser/server.mjs"]
