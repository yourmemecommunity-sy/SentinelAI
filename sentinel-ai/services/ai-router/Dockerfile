# The AI router is a LIBRARY, not a service (ADR-0005): it is compiled into the gateway image and runs in-process.
# There is therefore no ai-router container in docker-compose.yml. This image exists only to build and test the library
# in isolation (e.g. in CI):  docker build -f services/ai-router/Dockerfile .   (context: repository root)
FROM node:20-alpine
RUN corepack enable
WORKDIR /repo
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY services/ai-router services/ai-router
RUN pnpm install --frozen-lockfile --filter "@sentinelai/ai-router" \
 && pnpm --filter "@sentinelai/ai-router" build \
 && pnpm --filter "@sentinelai/ai-router" test
USER node
CMD ["node", "-e", "console.log('ai-router is a library compiled into the gateway; it has no server to run')"]
