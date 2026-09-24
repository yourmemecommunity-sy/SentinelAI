#!/usr/bin/env node
// Blocks until every migration bundled in this image has been applied, then exits 0 (timeout: exit 1).
// Runs as the RESTRICTED application role (e.g. a Kubernetes initContainer of the gateway): the gateway pod never needs
// the owner's credentials, and a new gateway version never serves traffic against an older schema.
//
//   DATABASE_URL=postgresql://sentinel_api:...@host/db [WAIT_TIMEOUT_S=600] node db/wait-for-schema.mjs
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const url = process.env.DATABASE_URL;
if (!url) { console.error("DATABASE_URL is required"); process.exit(2); }
const wanted = readdirSync(join(dirname(fileURLToPath(import.meta.url)), "migrations")).filter((f) => f.endsWith(".sql")).sort();
const deadline = Date.now() + Number(process.env.WAIT_TIMEOUT_S ?? 600) * 1000;
let last = "";

while (Date.now() < deadline) {
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 5000 });
  try {
    await client.connect();
    const { rows } = await client.query("SELECT name FROM schema_migrations WHERE name = ANY($1)", [wanted]);
    const missing = wanted.filter((w) => !rows.some((r) => r.name === w));
    if (missing.length === 0) { console.log(`schema ready: ${wanted.length} migrations applied`); process.exit(0); }
    last = `waiting for ${missing.length} migration(s): ${missing.join(", ")}`;
  } catch (err) {
    last = `waiting for the database: ${err.code ?? err.message}`;   // role not provisioned yet, DB starting, ...
  } finally {
    await client.end().catch(() => undefined);
  }
  console.log(last);
  await new Promise((r) => setTimeout(r, 3000));
}
console.error(`timed out: ${last}`);
process.exit(1);
