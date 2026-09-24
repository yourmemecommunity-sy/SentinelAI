import { readFileSync, readdirSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Every package the gateway imports at RUNTIME must be a production dependency.
 *
 * Found by the first real container build: `@sentinelai/shared-types` was a devDependency, but the gateway imports runtime
 * values from it (the enums its validation schemas are built from). Local installs include dev dependencies, so everything
 * worked; a production install (`pnpm deploy --prod`) omitted it and the gateway crashed on start. `import type` is erased at
 * compile time and is therefore allowed from devDependencies.
 */
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
const prod = new Set(Object.keys(pkg.dependencies ?? {}));
const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : p.endsWith(".ts") ? [p] : [];
  });
}

/** Package name of a bare specifier: "@scope/name/x" -> "@scope/name", "name/x" -> "name". */
const packageOf = (spec: string) => (spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]!);

function runtimeImports(src: string): string[] {
  const out: string[] = [];
  // import X from "p" | import { a } from "p" | import "p" | export ... from "p"  -- but NOT `import type` / `export type`
  const re = /^\s*(?:import|export)\s+(?!type\b)(?:[^'"]*?\sfrom\s+)?["']([^"']+)["']/gm;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    const spec = m[1]!;
    if (spec.startsWith(".") || spec.startsWith("/")) continue;
    out.push(spec);
  }
  // dynamic import("p")
  for (const m of src.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g)) if (!m[1]!.startsWith(".")) out.push(m[1]!);
  return out;
}

describe("production packaging", () => {
  const sources = files(join(ROOT, "src"));

  it("scans the gateway's source files", () => {
    expect(sources.length).toBeGreaterThan(20);
  });

  it("every runtime import resolves to a production dependency (or a Node builtin)", () => {
    const missing = new Map<string, string[]>();
    for (const f of sources) {
      for (const spec of runtimeImports(readFileSync(f, "utf8"))) {
        const name = packageOf(spec);
        if (builtins.has(spec) || builtins.has(name) || prod.has(name)) continue;
        missing.set(name, [...(missing.get(name) ?? []), f.slice(ROOT.length + 1)]);
      }
    }
    expect(Object.fromEntries(missing), "runtime imports that a production install would not provide").toEqual({});
  });

  it("the check itself distinguishes type-only imports", () => {
    expect(runtimeImports(`import type { A } from "dev-only";`)).toEqual([]);
    expect(runtimeImports(`import { ACTIONS } from "@sentinelai/shared-types";`)).toEqual(["@sentinelai/shared-types"]);
    expect(runtimeImports(`export { x } from "pkg/sub";`)).toEqual(["pkg/sub"]);
    expect(runtimeImports(`const m = await import("lazy");`)).toEqual(["lazy"]);
    expect(packageOf("@scope/name/deep")).toBe("@scope/name");
  });
});
