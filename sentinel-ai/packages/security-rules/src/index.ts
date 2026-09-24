/** Rule sets are versioned directories (v1, v2, ...) next to this package's src/. */
export const RULE_SET_VERSIONS = ["v1"] as const;
export type RuleSetVersion = (typeof RULE_SET_VERSIONS)[number];
