/**
 * The entity list and the non-overridable ("never ALLOW") set exist in Python (engine), TypeScript (shared-types,
 * gateway validation) and SQL (CHECK constraint). They must never drift: a gap in any one is a policy-bypass hole.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ACTIONS, ENTITY_TYPES, NEVER_ALLOW_ENTITIES, SEVERITIES } from "@sentinelai/shared-types";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const read = (p: string): string => readFileSync(resolve(ROOT, p), "utf8").replace(/\r\n/g, "\n"); // line-ending agnostic
const py = read("services/security-engine/app/models/types.py");
const sql = read("scripts/database/migrations/0001_init.sql");
const openapi = read("docs/api/openapi.yaml");

const block = (src: string, start: RegExp, end: string): string => {
  const m = start.exec(src);
  if (!m) throw new Error(`block not found: ${start}`);
  return src.slice(m.index, src.indexOf(end, m.index));
};
const sorted = (xs: readonly string[]) => [...xs].sort();

describe("Python / TypeScript / SQL / OpenAPI contracts agree", () => {
  const pyEntities = [...block(py, /class EntityType\(/, "THREAT_ENTITIES").matchAll(/^\s+([A-Z_]+) = "([A-Z_]+)"$/gm)].map((m) => m[1]!);
  const pyEnum = (name: string) => [...block(py, new RegExp(`class ${name}\\(`), "\n\n\n").matchAll(/^\s+([A-Z_]+) = "([A-Z_]+)"$/gm)].map((m) => m[1]!);
  const refs = (src: string) => [...src.matchAll(/EntityType\.([A-Z_]+)/g)].map((m) => m[1]!);

  it("entity types", () => {
    expect(pyEntities.length).toBeGreaterThan(20);
    expect(sorted(ENTITY_TYPES)).toEqual(sorted(pyEntities));
    const yamlEnum = block(openapi, /EntityType:\n\s+type: string\n\s+enum: \[/, "]").replace(/[\s\S]*enum: \[/, "");
    expect(sorted(yamlEnum.split(",").map((s) => s.trim()).filter(Boolean))).toEqual(sorted(ENTITY_TYPES));
  });

  it("actions and severities", () => {
    expect(sorted(ACTIONS)).toEqual(sorted(pyEnum("Action")));
    expect(sorted(SEVERITIES)).toEqual(sorted(pyEnum("Severity")));
  });

  it("never-ALLOW set = Python NEVER_ALLOW ∪ THREAT in TS and SQL", () => {
    const neverAllow = refs(block(py, /NEVER_ALLOW_ENTITIES = frozenset/, "})"));
    const threats = refs(block(py, /THREAT_ENTITIES = frozenset/, "})"));
    const expected = sorted([...neverAllow, ...threats]);
    expect(sorted(NEVER_ALLOW_ENTITIES)).toEqual(expected);
    const check = block(sql, /CONSTRAINT policy_rules_no_unsafe_allow/, "UNIQUE (policy_pk, position)");
    const sqlEntities = [...check.matchAll(/'([A-Z_]+)'/g)].map((m) => m[1]!).filter((v) => v !== "ALLOW" && v !== "CRITICAL");
    expect(sorted(sqlEntities)).toEqual(expected);
  });

  it("every SQL-listed and TS-listed never-allow entity is a real entity type", () => {
    for (const e of NEVER_ALLOW_ENTITIES) expect(ENTITY_TYPES).toContain(e);
  });
});
