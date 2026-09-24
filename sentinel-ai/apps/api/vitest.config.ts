import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"], testTimeout: 30_000, hookTimeout: 60_000,
    // One file at a time. Several e2e files each spawn real Python services (engine, document scanner, token vault) plus an
    // in-process Postgres; run in parallel they starve each other and time out on a developer machine, which looks like a
    // product failure but is only contention. Serial is slower and deterministic.
    fileParallelism: false,
  },
  resolve: {
    alias: {
      // Run against workspace sources so tests do not require a prior build.
      "@sentinelai/shared-types": fileURLToPath(new URL("../../packages/shared-types/src/index.ts", import.meta.url)),
      "@sentinelai/ai-router": fileURLToPath(new URL("../../services/ai-router/src/index.ts", import.meta.url)),
    },
  },
});
