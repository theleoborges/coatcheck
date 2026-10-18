FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/tsconfig.json ./packages/core/
COPY packages/provider-aws/package.json packages/provider-aws/tsconfig.json ./packages/provider-aws/
COPY packages/provider-env/package.json packages/provider-env/tsconfig.json ./packages/provider-env/
RUN npm ci
COPY packages/core/src/ ./packages/core/src/
COPY packages/provider-aws/src/ ./packages/provider-aws/src/
COPY packages/provider-env/src/ ./packages/provider-env/src/
RUN npm run build

FROM node:24-slim
# No system packages: certificates are generated in-process (core/src/ca.ts) and
# Node verifies upstream TLS against its bundled root store.
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/provider-aws/package.json ./packages/provider-aws/
COPY packages/provider-env/package.json ./packages/provider-env/
# Core plus both providers; COATCHECK_PROVIDER picks one at startup.
RUN npm ci --omit=dev
COPY --from=build /app/packages/core/dist/ ./packages/core/dist/
COPY --from=build /app/packages/provider-aws/dist/ ./packages/provider-aws/dist/
COPY --from=build /app/packages/provider-env/dist/ ./packages/provider-env/dist/

# 3128: HTTP(S) proxy + vault API. 8444: CDP WebSocket proxy (COATCHECK_CDP_ENABLED=1).
# Binds 127.0.0.1 by default — run as a sidecar sharing the agent's network namespace.
EXPOSE 3128 8444

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3128/_health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

USER node
CMD ["node", "packages/core/dist/cli.js"]
