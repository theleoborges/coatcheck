# ledger: the HMAC-protected service for the ledger-reconcile example. No dependencies.
FROM node:24-slim
WORKDIR /srv
COPY server.mjs data.json ./
USER node
EXPOSE 8443
CMD ["node", "server.mjs"]
