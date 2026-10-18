# Agent image for the coatcheck examples: Node 24 + curl, git, gh, Playwright (client only),
# and AWS CLI v2 when built with INSTALL_AWS_CLI=1 (vercel-release-report).
FROM node:24-slim
ARG GH_VERSION=2.62.0
ARG INSTALL_AWS_CLI=0
ARG AWS_CLI_VERSION=2.31.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq \
    && arch="$(dpkg --print-architecture)" \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${arch}.tar.gz" \
       | tar -xz -C /tmp \
    && mv "/tmp/gh_${GH_VERSION}_linux_${arch}/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh_* \
    && if [ "$INSTALL_AWS_CLI" = 1 ]; then \
         apt-get install -y --no-install-recommends unzip \
         && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m)-${AWS_CLI_VERSION}.zip" -o /tmp/awscliv2.zip \
         && unzip -q /tmp/awscliv2.zip -d /tmp \
         && /tmp/aws/install \
         && rm -rf /tmp/aws /tmp/awscliv2.zip \
         && apt-get purge -y unzip; \
       fi \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY harness/package.json harness/package-lock.json ./
RUN npm ci --omit=dev
COPY harness/src/ ./src/
COPY harness/system.md ./system.md
COPY entrypoint.sh /usr/local/bin/agent-entrypoint
# ESM imports ignore NODE_PATH: expose the installed packages (playwright-core) to scripts in /work.
RUN mkdir -p /work /out && ln -s /app/node_modules /work/node_modules && chown -h node:node /work /work/node_modules /out
# Root only for update-ca-certificates in the entrypoint; the agent runs as `node`.
ENTRYPOINT ["agent-entrypoint"]
CMD ["node", "/app/src/agent.ts", "/task.md"]
