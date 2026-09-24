# Dashboard image (Next.js standalone output). Build context MUST be the repository root:
#   docker build -f apps/dashboard/Dockerfile .
FROM node:20-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages/shared-types packages/shared-types
COPY apps/dashboard apps/dashboard
ENV NEXT_TELEMETRY_DISABLED=1 NEXT_OUTPUT=standalone
RUN pnpm install --frozen-lockfile --filter "@sentinelai/dashboard..." \
 && pnpm --filter "@sentinelai/dashboard..." --workspace-concurrency=1 build

FROM node:20-alpine
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
# Patch the base image (e.g. OpenSSL) and remove the package managers: the runtime only needs `node`. The npm CLI
# bundled in node:20-alpine carried every HIGH/CRITICAL finding of the Trivy scan (tar, glob, minimatch, ...), none of
# them reachable from the application, all of them attack surface.
RUN apk upgrade --no-cache && apk add --no-cache tini \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*
WORKDIR /app
# Standalone output mirrors the monorepo layout from outputFileTracingRoot, so the server lives under apps/dashboard.
COPY --from=build --chown=node:node /repo/apps/dashboard/.next/standalone ./
COPY --from=build --chown=node:node /repo/apps/dashboard/.next/static ./apps/dashboard/.next/static
COPY --from=build --chown=node:node /repo/apps/dashboard/public ./apps/dashboard/public
USER node
EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/dashboard/server.js"]
