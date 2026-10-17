FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-slim
# No system packages: certificates are generated in-process (src/ca.ts) and
# Node verifies upstream TLS against its bundled root store.
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist/ ./dist/

# 3128: HTTP(S) proxy + vault API. 8444: CDP WebSocket proxy (COATCHECK_CDP_ENABLED=1).
# Binds 127.0.0.1 by default — run as a sidecar sharing the agent's network namespace.
EXPOSE 3128 8444

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3128/_health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

USER node
CMD ["node", "dist/index.js"]
