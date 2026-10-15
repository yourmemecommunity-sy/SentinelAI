/**
 * DevicePulse API contracts. Versioned by directory: `v1` is schema_version "1.0". A breaking change gets a new directory
 * (v2) and both are served side by side until clients migrate; additive changes bump the minor version within v1.
 */
export * as v1 from "./v1/index.js";
export * from "./v1/index.js";
