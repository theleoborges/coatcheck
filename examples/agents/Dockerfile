# Agent image for the coatcheck examples: Node 24 + curl, git, gh, Playwright (client only).
FROM node:24-slim
ARG GH_VERSION=2.62.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${arch}.tar.gz" \
       | tar -xz -C /tmp \
    && mv "/tmp/gh_${GH_VERSION}_linux_${arch}/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh_*
WORKDIR /app
COPY harness/package.json harness/package-lock.json ./
RUN npm ci --omit=dev
COPY harness/src/ ./src/
COPY harness/system.md ./system.md
COPY entrypoint.sh /usr/local/bin/agent-entrypoint
RUN mkdir -p /work /out && chown node:node /work /out
# Root only for update-ca-certificates in the entrypoint; the agent runs as `node`.
ENTRYPOINT ["agent-entrypoint"]
CMD ["node", "/app/src/agent.ts", "/task.md"]
