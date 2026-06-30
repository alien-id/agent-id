// Alien Agent ID — Persistent interactive browser session.
//
// `open` launches the (unsealed) profile under patchright and runs a small
// localhost control server that holds the live context. Fine-grained action
// commands (snapshot/click/type/…) connect to it, so the agent can observe the
// page and act on it across many calls — like Playwright-MCP, but on our
// stealth patchright launch with the profile sealed in the vault.
//
// Observation model (Playwright-MCP style): `snapshot` tags every visible
// interactive element with a `data-aibref="eN"` attribute and returns a flat
// accessibility list [{ref, role, name, …}]. Actions then target an element by
// its ref (resolved to the `[data-aibref="eN"]` selector). Refs are valid until
// the next snapshot / navigation.
//
// Protocol: line-delimited JSON over a 127.0.0.1 TCP socket, gated by a random
// per-session token. Session coordinates live in
// <stateDir>/browser-sessions/<name>.json (0600).

import net from "node:net";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import { launchContext } from "./launch.mjs";
import { sealProfile } from "./profile-store.mjs";
import { openVault, loadAgentPrivateKey } from "@alien-id/agent-id-vault/lib/vault.mjs";
import { resolveOtp } from "./auto-login.mjs";

function sessionsDir(stateDir) {
  return path.join(stateDir, "browser-sessions");
}
export function sessionFilePath(stateDir, name) {
  return path.join(sessionsDir(stateDir), `${name}.json`);
}

// Runs in the page. Tags visible interactive elements and returns a flat list.
function snapshotInPage() {
  const SEL = [
    "a[href]", "button", "input:not([type=hidden])", "textarea", "select",
    "[role=button]", "[role=link]", "[role=textbox]", "[role=checkbox]",
    "[role=radio]", "[role=tab]", "[role=menuitem]", "[role=option]",
    "[contenteditable=true]", "summary", "[tabindex]:not([tabindex='-1'])",
  ].join(",");
  // Clear refs from a previous snapshot first: forms that swap in place (e.g.
  // multi-step IdP logins) leave stale data-aibref attributes, so a reused ref
  // like "e2" could match BOTH an old hidden element and a new one — and an action
  // would target the wrong (often invisible) element.
  for (const old of document.querySelectorAll("[data-aibref]")) old.removeAttribute("data-aibref");
  const out = [];
  let i = 0;
  const seen = new Set();
  for (const el of document.querySelectorAll(SEL)) {
    if (seen.has(el)) continue;
    seen.add(el);
    const r = el.getBoundingClientRect();
    const st = window.getComputedStyle(el);
    if (r.width === 0 || r.height === 0 || st.visibility === "hidden" || st.display === "none") {
      continue;
    }
    const ref = "e" + ++i;
    el.setAttribute("data-aibref", ref);
    const name = (
      el.getAttribute("aria-label") ||
      el.getAttribute("placeholder") ||
      (el.tagName === "INPUT" || el.tagName === "TEXTAREA" ? el.value : "") ||
      el.innerText ||
      el.getAttribute("title") ||
      el.getAttribute("name") ||
      ""
    ).replace(/\s+/g, " ").trim().slice(0, 100);
    out.push({
      ref,
      role: el.getAttribute("role") || el.tagName.toLowerCase(),
      name,
      ...(el.getAttribute("type") ? { type: el.getAttribute("type") } : {}),
    });
  }
  return { url: location.href, title: document.title, elements: out };
}

const sel = (ref) => `[data-aibref="${String(ref).replace(/["\\]/g, "")}"]`;
const ACTION_TIMEOUT = 15000;

// Unlock the vault non-interactively (agent-key slot) inside the session process,
// so a secret can be injected straight into the page without the controlling agent
// ever seeing the value.
async function openVaultAgentKey(stateDir) {
  const pk = await loadAgentPrivateKey(stateDir);
  if (!pk) throw new Error("vault: no agent key available to unlock");
  return openVault({ stateDir, privateKeyPem: pk });
}

async function dispatch(page, msg) {
  const p = msg.params || {};
  switch (msg.action) {
    case "info":
      return { url: page.url(), title: await page.title().catch(() => "") };
    case "navigate": {
      const resp = await page.goto(String(p.url), { waitUntil: "domcontentloaded", timeout: 30000 });
      return { url: page.url(), status: resp ? resp.status() : null };
    }
    case "back":
      await page.goBack({ waitUntil: "domcontentloaded" }).catch(() => {});
      return { url: page.url() };
    case "snapshot":
      return await page.evaluate(snapshotInPage);
    case "text":
      return { text: String(await page.evaluate(() => (document.body ? document.body.innerText : ""))).slice(0, Number(p.maxChars || 6000)) };
    case "click":
      await page.click(sel(p.ref), { timeout: ACTION_TIMEOUT });
      return { clicked: p.ref };
    case "type":
      await page.fill(sel(p.ref), String(p.text ?? ""), { timeout: ACTION_TIMEOUT });
      if (p.submit) await page.press(sel(p.ref), "Enter");
      return { typed: p.ref, submit: !!p.submit };
    case "fill": {
      const fields = Array.isArray(p.fields) ? p.fields : [];
      for (const f of fields) await page.fill(sel(f.ref), String(f.value ?? ""), { timeout: ACTION_TIMEOUT });
      return { filled: fields.map((f) => f.ref) };
    }
    case "fill-secret": {
      // Inject a vaulted secret into the element the agent identified. The agent
      // supplies { ref, cred: "name.field" } — never the value; nothing about the
      // value is returned or logged.
      const dot = String(p.cred || "").lastIndexOf(".");
      if (dot <= 0) throw new Error(`fill-secret needs cred "name.field" (got "${p.cred}")`);
      const credName = String(p.cred).slice(0, dot);
      const field = String(p.cred).slice(dot + 1);
      const vault = await openVaultAgentKey(msg._stateDir);
      try {
        const rec = vault.get(credName);
        if (!rec) throw new Error(`no credential "${credName}"`);
        const value = rec[field];
        if (typeof value !== "string" || !value) {
          throw new Error(`"${credName}.${field}" is not a usable string field`);
        }
        // CRITICAL: patchright's fill/press errors echo the value being typed, so
        // never let the raw error escape — it would leak the secret to the agent.
        try {
          await page.fill(sel(p.ref), value, { timeout: ACTION_TIMEOUT });
          if (p.submit) await page.press(sel(p.ref), "Enter");
        } catch {
          throw new Error(`fill-secret: could not fill "${p.ref}" — element not visible/editable (re-snapshot and retry)`);
        }
      } finally {
        vault.lock();
      }
      return { filled: p.ref, cred: p.cred };
    }
    case "fill-otp": {
      // Resolve the current 2FA code for a login/totp cred — generated from a
      // stored seed, or asked via the secure prompt — and type it.
      const credName = String(p.cred || "");
      const vault = await openVaultAgentKey(msg._stateDir);
      let code;
      try {
        const rec = vault.get(credName);
        if (!rec) throw new Error(`no credential "${credName}"`);
        const otpCred =
          rec.type === "totp"
            ? { name: credName, otp: "totp", totpSecret: rec.secret, period: rec.period, digits: rec.digits, algorithm: rec.algorithm }
            : rec;
        code = await resolveOtp(otpCred, {});
      } finally {
        vault.lock();
      }
      // Same leak guard as fill-secret: never surface the value-bearing error.
      try {
        await page.fill(sel(p.ref), code, { timeout: ACTION_TIMEOUT });
        if (p.submit !== false) await page.press(sel(p.ref), "Enter");
      } catch {
        throw new Error(`fill-otp: could not fill "${p.ref}" — element not visible/editable (re-snapshot and retry)`);
      }
      return { filled: p.ref, otp: true };
    }
    case "select":
      await page.selectOption(sel(p.ref), p.values, { timeout: ACTION_TIMEOUT });
      return { selected: p.ref };
    case "hover":
      await page.hover(sel(p.ref), { timeout: ACTION_TIMEOUT });
      return { hovered: p.ref };
    case "press":
      if (p.ref) await page.press(sel(p.ref), String(p.key));
      else await page.keyboard.press(String(p.key));
      return { pressed: p.key };
    case "scroll":
      await page.mouse.wheel(Number(p.dx || 0), Number(p.dy || 600));
      return { scrolled: true };
    case "screenshot": {
      const out = p.path ? String(p.path) : path.join(sessionsDir(msg._stateDir), `shot-${Date.now()}.png`);
      await page.screenshot({ path: out, fullPage: !!p.fullPage });
      return { screenshot: out };
    }
    case "eval":
      return { result: await page.evaluate(String(p.expression)) };
    case "wait":
      if (p.text) await page.getByText(String(p.text)).first().waitFor({ timeout: Number(p.ms || 15000) });
      else await page.waitForTimeout(Number(p.ms || 1000));
      return { waited: true };
    default:
      throw new Error(`unknown action: ${msg.action}`);
  }
}

// Launch the session and serve actions until `close` (or a signal). Blocks.
export async function runSession({ stateDir, name, headless, dekHex, profileFile, workDir }) {
  const ctx = await launchContext({ profileDir: workDir, headless });
  const page = ctx.pages()[0] || (await ctx.newPage());

  // Single, idempotent shutdown: close the browser, RESEAL the refreshed profile,
  // wipe the plaintext working copy, remove the session file, then exit. Guarded
  // so the ctx "close" event (which ctx.close() itself fires) can't re-enter and
  // call process.exit before the reseal/cleanup finishes.
  let finalizing = false;
  async function finalize() {
    if (finalizing) return;
    finalizing = true;
    try { await ctx.close(); } catch { /* already gone */ }
    try { await sealProfile({ stateDir, file: profileFile, dekHex, sourceDir: workDir }); } catch { /* best effort */ }
    try { await fs.rm(workDir, { recursive: true, force: true }); } catch { /* best effort */ }
    try { await fs.rm(sessionFilePath(stateDir, name), { force: true }); } catch { /* best effort */ }
    try { server.close(); } catch { /* not listening */ }
    process.exit(0);
  }

  const token = crypto.randomBytes(24).toString("hex");
  const server = net.createServer((sock) => {
    let buf = "";
    sock.on("data", async (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      let msg;
      try { msg = JSON.parse(line); } catch { sock.end(JSON.stringify({ ok: false, error: "bad json" }) + "\n"); return; }
      if (msg.token !== token) { sock.end(JSON.stringify({ ok: false, error: "bad token" }) + "\n"); return; }
      if (msg.action === "close") {
        sock.end(JSON.stringify({ ok: true, closed: true }) + "\n");
        finalize(); // reseals, wipes, and exits (once cleanup completes)
        return;
      }
      msg._stateDir = stateDir;
      try {
        const result = await dispatch(page, msg);
        sock.end(JSON.stringify({ ok: true, ...result }) + "\n");
      } catch (err) {
        sock.end(JSON.stringify({ ok: false, error: err.message || String(err) }) + "\n");
      }
    });
    sock.on("error", () => {});
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await fs.mkdir(sessionsDir(stateDir), { recursive: true, mode: 0o700 });
  await fs.writeFile(
    sessionFilePath(stateDir, name),
    JSON.stringify({ port, token, pid: process.pid, headless, startedAt: Date.now() }),
    { mode: 0o600 },
  );
  // Readiness signal: the agent runs `open` in the background and waits for this
  // line before issuing actions.
  process.stdout.write(JSON.stringify({ ok: true, ready: true, session: name, headless, port }) + "\n");

  // Reseal + clean up if the browser dies or we're terminated. finalize() handles
  // the exit itself, so these just invoke it (idempotent).
  ctx.on("close", () => { finalize(); });
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => { finalize(); });
  }
  return { port };
}

// Client: send one action to a running session, return its JSON reply.
export async function callSession(stateDir, name, action, params = {}, timeoutMs = 35000) {
  let info = null;
  for (let attempt = 0; attempt < 10 && !info; attempt++) {
    try {
      info = JSON.parse(await fs.readFile(sessionFilePath(stateDir, name), "utf8"));
    } catch {
      await new Promise((r) => setTimeout(r, 300)); // tolerate the open→ready race
    }
  }
  if (!info) {
    const e = new Error(`no open session named '${name}' — run \`open --name ${name}\` first`);
    e.code = "NO_SESSION";
    throw e;
  }
  return await new Promise((resolve, reject) => {
    const sock = net.connect(info.port, "127.0.0.1");
    let buf = "";
    const to = setTimeout(() => { sock.destroy(); reject(new Error("session timed out")); }, timeoutMs);
    sock.on("connect", () => sock.write(JSON.stringify({ token: info.token, action, params }) + "\n"));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        clearTimeout(to);
        try { resolve(JSON.parse(buf.slice(0, nl))); } catch (e) { reject(e); }
        sock.end();
      }
    });
    sock.on("error", (err) => { clearTimeout(to); const e = new Error(`session unreachable: ${err.message}`); e.code = "NO_SESSION"; reject(e); });
  });
}
