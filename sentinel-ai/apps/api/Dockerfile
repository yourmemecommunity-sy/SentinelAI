# Gateway image. Build context MUST be the repository root:  docker build -f apps/api/Dockerfile .
# The same image also runs the one-shot database jobs (migrations, app-role provisioning); see docker-compose.yml.
FROM node:20-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages/shared-types packages/shared-types
COPY services/ai-router services/ai-router
COPY apps/api apps/api
RUN pnpm install --frozen-lockfile --filter "@sentinelai/api..." \
 && pnpm --filter "@sentinelai/api..." --workspace-concurrency=1 build \
 && pnpm --filter "@sentinelai/api" deploy --prod /deploy

FROM node:20-alpine
ENV NODE_ENV=production
# Patch the base image (e.g. OpenSSL) and remove the package managers: the runtime only needs `node`. The npm CLI
# bundled in node:20-alpine carried every HIGH/CRITICAL finding of the Trivy scan (tar, glob, minimatch, ...), none of
# them reachable from the application, all of them attack surface.
RUN apk upgrade --no-cache && apk add --no-cache tini \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*
WORKDIR /app
# `pnpm deploy` yields a self-contained app: production dependencies only, workspace packages vendored in.
COPY --from=build --chown=node:node /deploy ./
# Database jobs live next to the app so `pg` resolves from its node_modules.
COPY --chown=node:node scripts/database ./db
USER node
EXPOSE 4000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
