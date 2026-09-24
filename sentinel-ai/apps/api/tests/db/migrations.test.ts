import { cpSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ESM script without type declarations
import { runMigrations } from "../../../../scripts/database/migrate.mjs";

const DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/database/migrations");
const adapter = (db: PGlite) => ({ exec: (s: string) => db.exec(s), query: (s: string, p?: unknown[]) => db.query(s, p) });

describe("migration runner", () => {
  it("applies every migration in order, is idempotent, and records checksums", async () => {
    const db = new PGlite();
    const files = readdirSync(DIR).filter((f) => f.endsWith(".sql")).sort();
    expect(await runMigrations(adapter(db), DIR)).toEqual(files);
    expect(await runMigrations(adapter(db), DIR)).toEqual([]);
    const { rows } = await db.query<{ name: string; checksum: string }>("SELECT name, checksum FROM schema_migrations ORDER BY name");
    expect(rows.map((r) => r.name)).toEqual(files);
    expect(rows.every((r) => /^[0-9a-f]{64}$/.test(r.checksum))).toBe(true);
    await db.close();
  });

  it("refuses to run when an applied migration was edited", async () => {
    const db = new PGlite();
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-mig-"));
    try {
      cpSync(DIR, tmp, { recursive: true });
      await runMigrations(adapter(db), tmp);
      writeFileSync(join(tmp, "0003_events_api_key.sql"), "-- tampered\n");
      await expect(runMigrations(adapter(db), tmp)).rejects.toThrow(/modified after being applied/);
    } finally { rmSync(tmp, { recursive: true, force: true }); await db.close(); }
  });

  it("rolls back a failing migration completely and reports which one", async () => {
    const db = new PGlite();
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-mig-"));
    try {
      writeFileSync(join(tmp, "0001_ok.sql"), "CREATE TABLE t1 (id int);");
      writeFileSync(join(tmp, "0002_bad.sql"), "CREATE TABLE t2 (id int); SELECT * FROM does_not_exist;");
      await expect(runMigrations(adapter(db), tmp)).rejects.toThrow(/0002_bad.sql failed/);
      expect((await db.query("SELECT to_regclass('t1') AS t1, to_regclass('t2') AS t2")).rows[0]).toEqual({ t1: "t1", t2: null });
      expect((await db.query<{ name: string }>("SELECT name FROM schema_migrations")).rows.map((r) => r.name)).toEqual(["0001_ok.sql"]);
    } finally { rmSync(tmp, { recursive: true, force: true }); await db.close(); }
  });
});
