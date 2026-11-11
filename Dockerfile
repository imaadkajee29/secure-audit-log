# Multi-stage build:
#   deps    -> production node_modules only (no dev tooling in the final image)
#   build   -> compiles TypeScript
#   runtime -> distroless: no shell, no package manager, runs as non-root
#
ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts blocks install-time scripts (a common supply-chain attack vector)
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:${NODE_VERSION}-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && mkdir -p /data

FROM gcr.io/distroless/nodejs${NODE_VERSION}-debian12:nonroot AS runtime
LABEL org.opencontainers.image.title="secure-audit-log" \
      org.opencontainers.image.description="Tamper-evident audit logging API" \
      org.opencontainers.image.source="https://github.com/imaadkajee29/secure-audit-log" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/data/audit.db

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY --from=build --chown=65532:65532 /data /data

USER 65532:65532
EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "dist/healthcheck.js"]

# Entrypoint of the distroless image is node itself.
CMD ["--disable-warning=ExperimentalWarning", "dist/server.js"]
