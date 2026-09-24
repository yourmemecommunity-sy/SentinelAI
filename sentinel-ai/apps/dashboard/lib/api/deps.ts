import type { BffDeps } from "./bff";

/** Server-only wiring for the BFF. The gateway URL never reaches the browser. */
export function serverDeps(): BffDeps {
  return {
    gatewayUrl: (process.env.GATEWAY_URL ?? "http://localhost:4000").replace(/\/+$/, ""),
    fetch: (input, init) => fetch(input, { ...init, cache: "no-store" }),
    secure: process.env.NODE_ENV === "production",
    ...(Number(process.env.MAX_FILE_BYTES) > 0 ? { maxUploadBytes: Number(process.env.MAX_FILE_BYTES) } : {}),
  };
}
