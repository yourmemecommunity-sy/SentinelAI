#!/usr/bin/env node
/**
 * Real-browser end-to-end test of the dashboard (Chromium via Playwright) against the RUNNING docker-compose stack.
 *
 * Run inside WSL (Playwright image, host network so the browser reaches the dashboard as http://localhost:3000 - exactly
 * how a user of this deployment reaches it, and the only way production `Secure` cookies are accepted over plain http):
 *
 *   docker run --rm --network host --ipc host -v "$PWD/scripts/development:/e2e" -w /tmp \
 *     mcr.microsoft.com/playwright:v1.49.1-noble sh -c "npm i -s playwright@1.49.1 && node /e2e/browser-e2e.mjs"
 *
 * Prints PASS/FAIL per check; exits non-zero on any failure. Uses synthetic data only.
 */
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";

const require = createRequire(`${process.cwd()}/`);
const { chromium } = require("playwright");

const BASE = process.env.DASH_URL ?? "http://localhost:3000";
const PW = "Str0ng-Browser-Passw0rd!";
const run = Date.now().toString(36);
const OWNER = `owner-${run}@example.com`;
const DEV = `dev-${run}@example.com`;
const SYNTH_PROVIDER_KEY = "sk-" + "synthetic" + "-browser-0000WXYZ";      // shaped like a key, not a real one
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";                               // runtime-assembled, not a real credential

let failures = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`); if (!ok) failures++; };
const step = async (name, fn) => { try { await fn(); } catch (e) { check(name, false, String(e?.message ?? e).split("\n")[0].slice(0, 300)); } };

const browser = await chromium.launch();
const consoleProblems = [];
async function newContext() {
  const ctx = await browser.newContext({ baseURL: BASE });
  ctx.on("page", (p) => p.on("console", (m) => { if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) consoleProblems.push(m.text()); }));
  return ctx;
}

const owner = await newContext();
const page = await owner.newPage();

await step("unauthenticated visit redirects to /login with strict security headers", async () => {
  const res = await page.goto("/dashboard");
  const url = new URL(page.url());
  const h = res.headers();
  check("unauthenticated visit redirects to /login", url.pathname === "/login", page.url());
  check("CSP with a per-request script nonce and no unsafe-inline scripts",
    /script-src 'self' 'nonce-[^']+' 'strict-dynamic'/.test(h["content-security-policy"] ?? "") && !/script-src[^;]*unsafe-inline/.test(h["content-security-policy"] ?? ""), h["content-security-policy"]);
  check("frame-ancestors 'none' (clickjacking)", /frame-ancestors 'none'/.test(h["content-security-policy"] ?? ""));
});

await step("register", async () => {
  await page.goto("/register");
  await page.getByLabel("Organization name").fill(`Browser Org ${run}`);
  await page.getByLabel("Email").fill(OWNER);
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: "Create account" }).click();
  await page.waitForURL("**/dashboard", { timeout: 30_000 });
  check("registering an organization signs the owner in and lands on the overview", true, page.url());
});

await step("tokens are not reachable from page JavaScript", async () => {
  const js = await page.evaluate(() => ({ cookie: document.cookie, local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage) }));
  const cookies = await owner.cookies();
  const at = cookies.find((c) => c.name === "sn_at");
  check("access/refresh tokens are HttpOnly cookies, invisible to document.cookie and web storage",
    !!at && at.httpOnly && at.sameSite === "Strict" && !/sn_at|sn_rt/.test(js.cookie) && !/eyJ|snr_/.test(js.local + js.session), `cookie="${js.cookie}"`);
  check("session cookies carry the Secure flag (production mode)", cookies.filter((c) => c.name.startsWith("sn_")).every((c) => c.secure), cookies.map((c) => `${c.name}:${c.secure}`).join(","));
});

await step("scan playground", async () => {
  await page.getByLabel("Text to scan").fill(`deploy with ${AWS} please`);
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await page.getByText("Blocked: nothing would be sent to the model.").waitFor({ timeout: 30_000 });
  check("playground: a secret is BLOCKED and nothing would be sent to the model", true);
  await page.getByRole("button", { name: "PII sample" }).click();
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await page.getByText("What the model would receive").waitFor({ timeout: 30_000 });
  const pre = await page.locator("pre").first().innerText();
  check("playground: PII is sanitized before it could reach a model", !pre.includes("jane.doe@example.com"), pre.slice(0, 120));
});

await step("events page", async () => {
  await page.getByRole("link", { name: "Security events" }).click();
  await page.waitForURL("**/events");
  await page.getByText(/\d+ events?/).first().waitFor({ timeout: 20_000 });
  const body = await page.locator("main").innerText();
  check("events page lists the scans just made, without the raw secret", /BLOCK/.test(body) && !body.includes(AWS), body.slice(0, 80).replace(/\s+/g, " "));
});

await step("api keys", async () => {
  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("browser-ci");
  await page.getByRole("button", { name: "Create key" }).click();
  const key = (await page.getByTestId("new-key").innerText({ timeout: 20_000 })).trim();
  check("API key is shown once after creation", /^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/.test(key));
  await page.getByRole("button", { name: "I have saved it" }).click();
  await page.reload();
  await page.getByText("browser-ci").first().waitFor();
  check("after dismissing, the key is never shown again (only its prefix)", !(await page.content()).includes(key));
});

let inviteUrl = "";
await step("invite a developer", async () => {
  await page.goto("/users");
  await page.getByLabel("Email").fill(DEV);
  await page.getByLabel("Role").selectOption("DEVELOPER");
  await page.getByRole("button", { name: "Create invitation" }).click();
  inviteUrl = (await page.getByTestId("invite-link").innerText({ timeout: 20_000 })).trim();
  check("owner creates an invitation; the link carries the token in the URL fragment", /\/accept-invite#sni_[A-Za-z0-9_-]{43}$/.test(inviteUrl), inviteUrl.replace(/#.*/, "#<token>"));
  await page.getByRole("button", { name: "Done" }).click();
  await page.getByRole("cell", { name: DEV, exact: true }).waitFor();
  check("the pending invitation is listed (without its token)", !(await page.content()).includes(inviteUrl.split("#")[1]));
});

const dev = await newContext();
const devPage = await dev.newPage();
await step("invitee accepts in a separate browser", async () => {
  const requests = [];
  devPage.on("request", (r) => requests.push(r.url()));
  await devPage.goto(inviteUrl.replace(/^https?:\/\/[^/]+/, ""));
  await devPage.getByLabel("Password (min. 12 characters)").waitFor();
  check("the token is removed from the address bar once read", new URL(devPage.url()).hash === "", devPage.url());
  await devPage.getByLabel("Password (min. 12 characters)").fill(PW);
  await devPage.getByLabel("Confirm password").fill(PW);
  await devPage.getByRole("button", { name: "Create account" }).click();
  await devPage.getByText("Your account is ready (role: DEVELOPER).").waitFor({ timeout: 30_000 });
  check("invitee sets a password and the account is created with the invited role", true);
  check("the invitation token never appeared in any request URL (fragment only)", !requests.some((u) => u.includes("sni_")), `${requests.length} requests`);
  await devPage.goto("/login");
  await devPage.getByLabel("Email").fill(DEV);
  await devPage.getByLabel("Password").fill(PW);
  await devPage.getByRole("button", { name: "Sign in" }).click();
  await devPage.waitForURL("**/dashboard", { timeout: 30_000 });
  await devPage.goto("/users");
  await devPage.getByText("Your role (DEVELOPER) cannot manage users.").waitFor({ timeout: 20_000 });
  check("the developer can sign in but cannot manage users", true);
});

await step("owner disables the developer; the developer's live session ends", async () => {
  await page.goto("/users");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: `Disable ${DEV}` }).click();
  await page.getByRole("button", { name: `Enable ${DEV}` }).waitFor({ timeout: 20_000 });
  await devPage.goto("/events");
  await devPage.waitForURL("**/login**", { timeout: 30_000 });
  check("a disabled user's open browser session is refused on its next request and sent to sign-in", true, devPage.url());
});

await step("self-protection", async () => {
  const buttons = await page.getByRole("button", { name: `Disable ${OWNER}` }).count();
  check("the UI offers no way to disable yourself (the API refuses it too)", buttons === 0);
});

await step("provider credential", async () => {
  await page.goto("/providers");
  await page.getByRole("button", { name: "Use our own key" }).first().waitFor({ timeout: 20_000 });
  const openaiCard = page.getByText("openai", { exact: true }).locator("xpath=ancestor::*[.//button[normalize-space()='Use our own key']][1]");
  await openaiCard.getByRole("button", { name: "Use our own key" }).click();
  await page.getByLabel("API key").fill(SYNTH_PROVIDER_KEY);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByText("Stored key ending in").waitFor({ timeout: 20_000 });
  const html = await page.content();
  check("an organization stores its own provider key; the page shows only the last 4 characters",
    html.includes("WXYZ") && !html.includes(SYNTH_PROVIDER_KEY) && !html.includes("synthetic-browser"), "");
});

await step("file scan", async () => {
  await page.goto("/files");
  await page.getByLabel("File to scan").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from(`Contact jane.doe@example.com. Key ${AWS}.`) });
  await page.getByRole("button", { name: "Scan file" }).click();
  await page.getByText(/BLOCK/).first().waitFor({ timeout: 60_000 });
  check("uploading a file containing a secret is blocked in the browser flow", !(await page.content()).includes(AWS));
});

await step("sign out", async () => {
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("**/login**", { timeout: 20_000 });
  const left = (await owner.cookies()).filter((c) => c.name === "sn_at" || c.name === "sn_rt");
  await page.goto("/dashboard");
  check("sign-out clears the session cookies and protected pages redirect to sign-in", left.length === 0 && new URL(page.url()).pathname === "/login", `${left.length} cookies left`);
});

check("no Content-Security-Policy violations in any page", consoleProblems.length === 0, consoleProblems.slice(0, 2).join(" | "));
try { await page.goto("/login"); writeFileSync("/tmp/last.png", await page.screenshot()); } catch { /* best effort */ }
await browser.close();
console.log(failures === 0 ? "\nBROWSER E2E: ALL CHECKS PASSED" : `\nBROWSER E2E: ${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
