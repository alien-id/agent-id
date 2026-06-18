#!/usr/bin/env node

// One-time, **no-Cloud-Console** setup for the Gmail demo: "log into Gmail once
// in a real browser (or reuse the session you already have open), and the agent
// reads mail forever without ever seeing a cookie."
//
// Unlike examples/gmail-login-bootstrap.mjs (which needs a registered OAuth
// client), this path needs NOTHING from Google Cloud Console. It captures your
// browser's Gmail web session cookies and stores them as a `cookie-jar`
// credential in the vault. The proxy already injects cookie-jars as a `Cookie:`
// header, so the agent then reads the cookie-authed Gmail Atom feed through the
// proxy and never sees a secret.
//
// TWO CAPTURE MODES:
//
//   --browser firefox  (smoothest — reuses your ALREADY-OPEN session)
//     Firefox stores cookies UNENCRYPTED in a SQLite DB (cookies.sqlite). We
//     read your default profile's Google cookies directly — no browser launch,
//     no re-login. Firefox can stay open; we read a consistent snapshot copy.
//
//   --browser chrome  (launches a browser; you sign in once)
//     Chrome encrypts cookie values with the OS keychain, so we can't read them
//     off disk. Instead we launch Chrome over the DevTools Protocol (CDP) with a
//     throwaway profile, you sign into Gmail once, and we capture the session's
//     cookies. Use --reuse-profile <dir> to reuse a logged-in Chrome profile
//     (Chrome must be CLOSED). Requires Node >= 22 (global WebSocket).
//
// The cookie values are NEVER printed, echoed to the transcript, or placed on a
// command line / in shell history. After this runs, the agent only ever types
// the credential name ("gmail").
//
// TRADEOFF (read this): Google rotates session cookies (the __Secure-*PSIDTS
// pair refreshes periodically) and may invalidate a session it flags as
// automated. A captured jar is good for a demo and for a while, but it is NOT as
// durable as the OAuth refresh-token path. Re-run this bootstrap to refresh the
// jar when reads start returning 401 / redirect-to-login.
//
// Usage:
//   node examples/gmail-cookie-bootstrap.mjs \
//     --state-dir <VAULT_DIR> \
//     [--browser firefox|chrome|auto]   # default: auto (firefox if a profile
//                                        #   with cookies is found, else chrome)
//     [--profile <dir|name>]            # firefox: profile dir or name to read
//                                        # chrome:  via --reuse-profile instead
//     [--passphrase-file <path>]        # else the vault prompts on /dev/tty
//     [--name gmail]                    # credential name the agent will use
//     [--chrome <path>]                 # chrome mode: browser binary
//     [--reuse-profile <dir>]           # chrome mode: reuse a logged-in profile
//     [--domains mail.google.com]       # hosts the cookie-jar is scoped to
//     [--timeout-sec 300]              # chrome mode: how long to wait for login

import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  mkdtemp,
  writeFile,
  rm,
  readFile,
  access,
  copyFile,
  readdir,
} from "node:fs/promises";
import { rmSync } from "node:fs";

// Remove a temp path even if the user Ctrl-C's during the interactive vault
// prompt (the default SIGINT disposition would otherwise skip the `finally`,
// leaving cleartext secrets in /tmp). Returns a disposer to call on the happy
// path; it unregisters the handlers.
function guardTempPath(p) {
  const onSignal = (sig) => {
    try {
      rmSync(p, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
    process.exit(sig === "SIGTERM" ? 143 : 130);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  };
}
import { parseArgs } from "node:util";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_VAULT_CLI = path.resolve(HERE, "../plugins/agent-id-vault/bin/cli.mjs");

// The host the agent will read through the proxy. The Atom feed lives here and
// is authenticated purely by the browser session cookies — no SAPISIDHASH, no
// OAuth — which is exactly why it works for a captured cookie-jar.
const GMAIL_HOST = "mail.google.com";
// The account-indexed feed path. /mail/feed/atom 302-redirects here; u/0 is the
// primary signed-in account. Verified to return 200 from a captured cookie jar.
const ATOM_PATH = "/mail/u/0/feed/atom";

// Cookies that signal a fully-established Google account session. We wait for /
// require these before capturing so we don't grab a half-signed-in jar.
const SESSION_MARKERS = ["SID", "__Secure-1PSID"];

function die(msg) {
  console.error(`\n✗ ${msg}\n`);
  process.exit(1);
}

// ─── Pure helpers (exported for tests; no I/O) ──────────────────────────────────

// Would a cookie with this `domain` attribute be sent to https://<host>/?
// Firefox's moz_cookies.host and CDP both give ".google.com" (any subdomain) or
// "mail.google.com" (host-only). RFC 6265 §5.1.3 domain-matching, simplified.
export function cookieAppliesToHost(domain, host) {
  if (typeof domain !== "string" || !domain) return false;
  const d = domain.toLowerCase().replace(/^\./, "");
  const h = host.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

// Do the captured cookies include the markers that mean "signed in"?
export function isGoogleSessionReady(cookies) {
  if (!Array.isArray(cookies)) return false;
  const present = new Set(cookies.filter((c) => c && c.value).map((c) => c.name));
  return SESSION_MARKERS.every((m) => present.has(m));
}

// Reduce raw cookies ({ name, value, domain }) to the flat { name: value } jar
// the vault stores, keeping only cookies the browser would send to `host`. When
// the same name exists for several domains (e.g. ".google.com" and host-only
// "mail.google.com"), keep the most specific (longest, non-dot-prefixed)
// domain — that's what the browser would actually send.
export function buildCookieJar(cookies, host = GMAIL_HOST) {
  const applicable = (cookies || []).filter(
    (c) => c && typeof c.value === "string" && cookieAppliesToHost(c.domain, host),
  );
  const specificity = (c) => (c.domain.startsWith(".") ? 0 : 1000) + c.domain.length;
  const byName = new Map();
  for (const c of applicable) {
    const prev = byName.get(c.name);
    if (!prev || specificity(c) > specificity(prev)) byName.set(c.name, c);
  }
  const jar = {};
  for (const [name, c] of byName) jar[name] = c.value;
  return jar;
}

// Parse a Firefox profiles.ini and return the default profile's { path,
// isRelative }, or null. Preference order matches Firefox itself:
//   1. the [Install…] section's Default=<path> (the profile this install uses)
//   2. a [ProfileN] with Default=1
//   3. a profile whose Name/Path ends with "default-release"
//   4. the first profile
export function pickFirefoxProfile(profilesIniText) {
  const sections = [];
  let cur = null;
  for (const raw of String(profilesIniText).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    const head = line.match(/^\[(.+)\]$/);
    if (head) {
      cur = { header: head[1], kv: {} };
      sections.push(cur);
      continue;
    }
    if (!cur) continue;
    const eq = line.indexOf("=");
    if (eq > 0) cur.kv[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  const profiles = sections.filter((s) => /^Profile/i.test(s.header));

  const install = sections.find((s) => /^Install/i.test(s.header));
  if (install && install.kv.Default) {
    return { path: install.kv.Default, isRelative: true };
  }
  const flagged = profiles.find((s) => s.kv.Default === "1");
  const byName = profiles.find((s) =>
    /default-release$/i.test(s.kv.Name || "") || /default-release$/i.test(s.kv.Path || ""),
  );
  const chosen = flagged || byName || profiles[0];
  if (!chosen || !chosen.kv.Path) return null;
  return { path: chosen.kv.Path, isRelative: chosen.kv.IsRelative !== "0" };
}

// ─── Firefox: read cookies straight from cookies.sqlite ─────────────────────────

function firefoxRootCandidates() {
  const home = os.homedir();
  return [
    path.join(home, ".mozilla", "firefox"),
    path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
    path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    // macOS
    path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
    // windows
    path.join(process.env.APPDATA || "", "Mozilla", "Firefox", "Profiles"),
  ].filter(Boolean);
}

async function resolveFirefoxProfileDir(explicit) {
  // Explicit absolute dir → use as-is.
  if (explicit && path.isAbsolute(explicit)) {
    await access(path.join(explicit, "cookies.sqlite")).catch(() =>
      die(`No cookies.sqlite under --profile ${explicit}`),
    );
    return explicit;
  }
  for (const root of firefoxRootCandidates()) {
    // Explicit name → look for it directly under this root.
    if (explicit) {
      const dir = path.join(root, explicit);
      try {
        await access(path.join(dir, "cookies.sqlite"));
        return dir;
      } catch {
        /* try the profiles.ini route / other roots */
      }
    }
    // profiles.ini-driven default.
    let ini;
    try {
      ini = await readFile(path.join(root, "profiles.ini"), "utf8");
    } catch {
      continue;
    }
    const picked = pickFirefoxProfile(ini);
    if (!picked) continue;
    const dir = picked.isRelative ? path.join(root, picked.path) : picked.path;
    try {
      await access(path.join(dir, "cookies.sqlite"));
      return dir;
    } catch {
      /* default profile has no cookie db yet */
    }
  }
  return null;
}

// Read Google cookies from a profile's cookies.sqlite. We copy the DB (+ any
// -wal/-shm) to a temp dir first so we get a consistent snapshot even while
// Firefox is running, and never touch the live file. Returns
// [{ name, value, domain }].
export async function readFirefoxCookies(profileDir) {
  const { DatabaseSync } = await import("node:sqlite");
  const tmp = await mkdtemp(path.join(os.tmpdir(), "agentid-ffcookies-"));
  try {
    for (const suffix of ["", "-wal", "-shm"]) {
      const src = path.join(profileDir, `cookies.sqlite${suffix}`);
      try {
        await copyFile(src, path.join(tmp, `cookies.sqlite${suffix}`));
      } catch {
        if (suffix === "") throw new Error(`cookies.sqlite not found in ${profileDir}`);
      }
    }
    const db = new DatabaseSync(path.join(tmp, "cookies.sqlite"));
    try {
      // buildCookieJar re-filters precisely to mail.google.com, so a loose SQL
      // match here is safe; it just narrows the rows we pull.
      const rows = db
        .prepare("SELECT name, value, host FROM moz_cookies WHERE host LIKE '%google.com'")
        .all();
      return rows.map((r) => ({ name: r.name, value: r.value, domain: r.host }));
    } finally {
      db.close();
    }
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

async function captureFromFirefox(explicitProfile) {
  const profileDir = await resolveFirefoxProfileDir(explicitProfile);
  if (!profileDir) {
    die(
      "Could not find a Firefox profile with cookies. Pass --profile <dir|name>, " +
        "or use --browser chrome.",
    );
  }
  console.error(`  reading    : ${path.join(profileDir, "cookies.sqlite")} (snapshot copy)\n`);
  const cookies = await readFirefoxCookies(profileDir);
  if (!isGoogleSessionReady(cookies)) {
    die(
      "That Firefox profile isn't signed into Google (no SID/__Secure-1PSID). " +
        "Open Gmail in Firefox, sign in, then re-run — or pass --profile <name> " +
        "for the right profile.",
    );
  }
  return buildCookieJar(cookies, GMAIL_HOST);
}

// ─── Chrome: launch + capture over the DevTools Protocol ────────────────────────

function chromeCandidates() {
  if (process.platform === "darwin") {
    return [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
  }
  if (process.platform === "win32") {
    const pf = process.env["PROGRAMFILES"] || "C:\\Program Files";
    const pf86 = process.env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)";
    return [
      `${pf}\\Google\\Chrome\\Application\\chrome.exe`,
      `${pf86}\\Google\\Chrome\\Application\\chrome.exe`,
      `${pf86}\\Microsoft\\Edge\\Application\\msedge.exe`,
    ];
  }
  const names = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "microsoft-edge",
  ];
  const resolved = [];
  for (const n of names) {
    try {
      resolved.push(execFileSync("command", ["-v", n], { shell: "/bin/sh" }).toString().trim());
    } catch {
      /* not on PATH */
    }
  }
  return resolved.concat([
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
  ]);
}

async function findChrome(explicit) {
  const tryList = [explicit, process.env.CHROME_PATH, ...chromeCandidates()].filter(Boolean);
  for (const p of tryList) {
    try {
      await access(p);
      return p;
    } catch {
      /* keep looking */
    }
  }
  die(
    "Could not find Chrome/Chromium. Install one, pass --chrome <path> " +
      "(or $CHROME_PATH), or use --browser firefox.",
  );
}

async function readDevToolsPort(userDataDir, timeoutMs = 20000) {
  const portFile = path.join(userDataDir, "DevToolsActivePort");
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const txt = await readFile(portFile, "utf8");
      const port = parseInt(txt.split("\n")[0].trim(), 10);
      if (Number.isInteger(port) && port > 0) return port;
    } catch {
      /* not written yet */
    }
    await sleep(150);
  }
  throw new Error("Chrome did not expose a DevTools port in time");
}

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on("error", reject);
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function connectCdp(port) {
  const version = await httpGetJson(`http://127.0.0.1:${port}/json/version`);
  const wsUrl = version.webSocketDebuggerUrl;
  if (!wsUrl) throw new Error("CDP /json/version had no webSocketDebuggerUrl");
  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error("CDP WebSocket error")), { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  ws.addEventListener("message", (ev) => {
    let msg;
    try {
      msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
    } catch {
      return;
    }
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`CDP ${msg.error.message || JSON.stringify(msg.error)}`));
      else resolve(msg.result);
    }
  });
  const call = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  return { call, close: () => ws.close() };
}

async function captureFromChrome(args) {
  const chromePath = await findChrome(args.chrome);
  const tmpProfile = args["reuse-profile"]
    ? null
    : await mkdtemp(path.join(os.tmpdir(), "agentid-chrome-"));
  const userDataDir = args["reuse-profile"] || tmpProfile;
  const timeoutMs = Math.max(30, parseInt(args["timeout-sec"], 10) || 300) * 1000;

  console.error(`  browser    : ${chromePath}`);
  console.error(
    `  profile    : ${userDataDir}${args["reuse-profile"] ? " (reused)" : " (throwaway)"}\n`,
  );

  const child = spawn(
    chromePath,
    [
      `--user-data-dir=${userDataDir}`,
      "--remote-debugging-port=0",
      "--no-first-run",
      "--no-default-browser-check",
      "--new-window",
      `https://${GMAIL_HOST}/mail/u/0/`,
    ],
    { stdio: "ignore", detached: false },
  );
  child.on("error", (e) => die(`Failed to launch Chrome: ${e.message}`));

  let cdp = null;
  try {
    const port = await readDevToolsPort(userDataDir).catch((e) => {
      if (args["reuse-profile"]) {
        die(
          `${e.message}. If you passed --reuse-profile, make sure that Chrome ` +
            "profile is fully CLOSED before running (a running Chrome holds a lock).",
        );
      }
      die(e.message);
    });
    cdp = await connectCdp(port);

    console.error("A browser window opened on Gmail.");
    console.error("→ Sign in (or you're already in) and let your inbox load.");
    console.error("  Waiting for the Google session… (Ctrl-C to abort)\n");

    const start = Date.now();
    for (;;) {
      const { cookies } = await cdp.call("Storage.getCookies");
      if (isGoogleSessionReady(cookies)) {
        await sleep(1500); // settle so mail-host cookies (OSID/COMPASS) land too
        const fresh = await cdp.call("Storage.getCookies");
        return buildCookieJar(fresh.cookies, GMAIL_HOST);
      }
      if (Date.now() - start > timeoutMs) {
        die("Timed out waiting for sign-in. Re-run and complete the Google login.");
      }
      await sleep(1500);
    }
  } finally {
    if (cdp) cdp.close();
    try {
      child.kill("SIGTERM");
    } catch {
      /* already gone */
    }
    if (tmpProfile) await rm(tmpProfile, { recursive: true, force: true });
  }
}

// ─── Store the jar in the vault ─────────────────────────────────────────────────

async function storeJarInVault(args, jar) {
  const cookieNames = Object.keys(jar || {});
  if (!isGoogleSessionReady(cookieNames.map((n) => ({ name: n, value: jar[n] })))) {
    die("Did not capture a complete Google session. Re-run and finish signing in.");
  }

  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "agentid-jar-"));
  const jarFile = path.join(tmpDir, "jar.json");
  const unguard = guardTempPath(tmpDir);
  try {
    await writeFile(jarFile, JSON.stringify(jar), { mode: 0o600 });
    const cliArgs = [
      args["vault-cli"],
      "add",
      "--state-dir",
      args["state-dir"],
      "--name",
      args.name,
      "--type",
      "cookie-jar",
      "--domains",
      args.domains,
      "--jar-file",
      jarFile,
      "--description",
      "Gmail web session (captured cookies) — reads the Atom feed",
    ];
    if (args["passphrase-file"]) cliArgs.push("--passphrase-file", args["passphrase-file"]);

    console.error(`Captured ${cookieNames.length} cookies. Storing the credential in the vault…\n`);
    const code = await new Promise((resolve) => {
      const c = spawn(process.execPath, cliArgs, { stdio: "inherit" });
      c.on("close", resolve);
    });
    if (code !== 0) die(`vault add exited with code ${code}`);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
    unguard();
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function firefoxProfileExists() {
  for (const root of firefoxRootCandidates()) {
    try {
      const entries = await readdir(root);
      for (const e of entries) {
        try {
          await access(path.join(root, e, "cookies.sqlite"));
          return true;
        } catch {
          /* keep scanning */
        }
      }
    } catch {
      /* no such root */
    }
  }
  return false;
}

async function main() {
  const { values: args } = parseArgs({
    options: {
      "state-dir": { type: "string" },
      "passphrase-file": { type: "string" },
      "vault-cli": { type: "string", default: DEFAULT_VAULT_CLI },
      name: { type: "string", default: "gmail" },
      browser: { type: "string", default: "auto" },
      profile: { type: "string" },
      chrome: { type: "string" },
      "reuse-profile": { type: "string" },
      domains: { type: "string", default: GMAIL_HOST },
      "timeout-sec": { type: "string", default: "300" },
    },
  });

  if (!args["state-dir"]) die("--state-dir is required (where the vault.enc lives)");

  let browser = (args.browser || "auto").toLowerCase();
  if (browser === "auto") {
    browser = (await firefoxProfileExists()) ? "firefox" : "chrome";
  }
  if (browser !== "firefox" && browser !== "chrome") {
    die(`--browser must be firefox, chrome, or auto (got ${args.browser})`);
  }

  console.error("\nAgent ID — Gmail cookie capture (no Cloud Console)");
  console.error(`  credential : ${args.name}`);
  console.error(`  mode       : ${browser}`);
  console.error(`  vault dir  : ${args["state-dir"]}`);

  const jar =
    browser === "firefox" ? await captureFromFirefox(args.profile) : await captureFromChrome(args);

  await storeJarInVault(args, jar);

  console.error("\n✓ Done. The agent can now read mail through the proxy with no secret in sight:\n");
  console.error(`   curl http://127.0.0.1:48771/${args.name}/${GMAIL_HOST}${ATOM_PATH}\n`);
  console.error("The proxy injects the captured session cookies; the agent only types the name.");
  console.error("Nothing sensitive was printed; the temp files were removed (incl. on Ctrl-C).");
  console.error(
    "\nNote: Google rotates session cookies — if reads start 401ing or redirect to\n" +
      "login, just re-run this bootstrap to refresh the jar.\n",
  );
}

// Only run when invoked directly, so tests can import the pure helpers above.
const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((err) => die(err.message || String(err)));
}
