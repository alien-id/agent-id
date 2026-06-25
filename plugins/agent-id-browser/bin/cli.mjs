#!/usr/bin/env node

// Alien Agent ID — Browser plugin CLI.
//
// A universal browser the agent can drive, with the logged-in profile sealed in
// the vault. One-time HEADED login establishes a session; afterwards the agent
// drives the browser HEADLESS by default (no window) to read/fetch any site.
//
//   login  --name N [--url START] [--account LABEL] [--headed-default]
//          one-time: opens a real window, you sign in and close it; the profile
//          is then sealed into the vault (browser-profile credential + DEK).
//   read   --name N --url URL [--headed] [--max-chars K]
//          navigate (headless by default) and return the page's text + final URL.
//   fetch  --name N --url URL [--headed] [--max-chars K]
//          authenticated HTTP GET via the session (e.g. an API or Atom feed).
//   status [--name N]   list sealed profiles; reports unlocked / sealed / account.
//
// Vault precondition: the vault MUST be unlocked. Unlock order: agent-key slot
// (auto) → passphrase (--passphrase-file / --passphrase-env) → owner-approval
// (the owner approves in the Alien app; the SAME app-unlock the proxy uses, but
// driven directly — no control plane needed). If none is available, every command
// emits a structured VAULT_LOCKED result — the agent must STOP and ask the owner
// to unlock, never retry blindly.
//
// Unlock flags: --passphrase-file F | --passphrase-env V | --no-agent-key |
//               --no-owner-approval

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";
import { openVault, loadAgentPrivateKey } from "../../agent-id-vault/lib/vault.mjs";

import {
  newDek,
  sealProfile,
  unsealProfile,
  sealedProfileExists,
} from "../lib/profile-store.mjs";
import { launchContext } from "../lib/launch.mjs";
import { looksLoggedOut } from "../lib/session.mjs";
import { runSession, callSession } from "../lib/session-server.mjs";
import { hasOwnerApproval, unlockViaOwnerApproval } from "../lib/unlock.mjs";

// Bridge the plugin path vars into the environment. Claude Code SUBSTITUTES
// ${CLAUDE_PLUGIN_DATA}/${CLAUDE_PLUGIN_ROOT} into skill text but only EXPORTS
// them to hook/MCP processes — not to ordinary skill Bash commands. So the skill
// passes them as `--plugin-data` / `--plugin-root` flags (with the path already
// substituted in), and we copy them into process.env here so lib/launch.mjs can
// locate the runtime-installed patchright uniformly (hook env or flag, same code).
for (let i = 2; i < process.argv.length - 1; i++) {
  const v = process.argv[i + 1];
  if (typeof v !== "string" || v.includes("${")) continue; // skip unsubstituted
  if (process.argv[i] === "--plugin-data" && !process.env.CLAUDE_PLUGIN_DATA) {
    process.env.CLAUDE_PLUGIN_DATA = v;
  } else if (process.argv[i] === "--plugin-root" && !process.env.CLAUDE_PLUGIN_ROOT) {
    process.env.CLAUDE_PLUGIN_ROOT = v;
  }
}

// ─── Vault unlock (non-interactive; surface VAULT_LOCKED rather than hang) ────────

// Unlock order: agent-key (auto) → passphrase (if given) → owner-approval ("approve
// in the Alien app"). `allowOwnerApproval:false` skips the app prompt (used by
// `status`, which should just report locked, not page the owner). If nothing
// works, throws VAULT_LOCKED so the agent stops and asks the owner.
async function openVaultUnlocked(flags, { allowOwnerApproval = true } = {}) {
  const stateDir = resolveStateDir(flags);
  const useAgentKey = flags["agent-key"] !== false; // --no-agent-key opts out
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;

  let passphrase = null;
  if (flags["passphrase-file"]) {
    passphrase = (await fs.readFile(flags["passphrase-file"], "utf8")).replace(/\n$/, "");
  } else if (flags["passphrase-env"]) {
    passphrase = process.env[flags["passphrase-env"]];
    if (!passphrase) {
      const e = new Error(`env var ${flags["passphrase-env"]} is not set`);
      e.code = "VAULT_LOCKED";
      throw e;
    }
  }

  // 1) Non-interactive: agent-key and/or passphrase.
  if (privateKeyPem || passphrase) {
    try {
      return await openVault({ stateDir, privateKeyPem, passphrase });
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // wrong/again — fall through to owner-approval if available
    }
  }

  // 2) App unlock: owner-approval (unless --no-owner-approval, or caller opted out).
  if (allowOwnerApproval && flags["owner-approval"] !== false && (await hasOwnerApproval(stateDir))) {
    try {
      stderr("Vault locked — approval request sent to your Alien app; approve it to continue…");
      return await unlockViaOwnerApproval({
        stateDir,
        onPrompt: ({ deepLink }) =>
          stderr(
            deepLink
              ? `Approve the vault unlock in your Alien app: ${deepLink}`
              : "Approve the vault unlock in your Alien app.",
          ),
      });
    } catch (err) {
      const e = new Error(`owner-approval unlock failed — ${err.message}`);
      e.code = "VAULT_LOCKED";
      throw e;
    }
  }

  // 3) Nothing available.
  const e = new Error("no agent-key slot, no passphrase, and no owner-approval slot");
  e.code = "VAULT_LOCKED";
  throw e;
}

function emitLocked(message) {
  outputJson({
    ok: false,
    error: "VAULT_LOCKED",
    action: "ask_owner_to_unlock",
    message:
      `The vault is locked (${message}). STOP and ask the owner to unlock it — ` +
      "provide --passphrase-file, or ensure an agent-key slot exists. Do not retry until unlocked.",
  });
  process.exitCode = 1;
}

function handleErr(err) {
  if (err.code === "VAULT_LOCKED") return emitLocked(err.message);
  if (err.code === "PATCHRIGHT_MISSING") return outputError(err.message);
  if (err.code === "NO_PROFILE") {
    outputJson({ ok: false, error: "NO_PROFILE", message: err.message });
    process.exitCode = 1;
    return;
  }
  if (err.code === "VAULT_NOT_FOUND") return outputError(err.message);
  return outputError(err.message || String(err));
}

// `--headed` → headed; `--headless` → headless; otherwise null (use cred default).
function resolveHeadless(flags) {
  if (flags.headed === true) return false;
  if (flags.headless === true) return true;
  if (flags.headless === false) return false;
  return null;
}

// Wait for the user to finish the headed login: window/context closed, or timeout.
function waitForUserClose(ctx, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let iv;
    let to;
    const finish = () => {
      if (done) return;
      done = true;
      clearInterval(iv);
      clearTimeout(to);
      resolve();
    };
    ctx.once("close", finish);
    iv = setInterval(() => {
      try {
        if (ctx.pages().length === 0) finish();
      } catch {
        finish();
      }
    }, 1000);
    to = setTimeout(finish, timeoutMs);
  });
}

// ─── Profile lifecycle: unseal → run → reseal → wipe ──────────────────────────────

async function withProfile({ flags, name, headless, action }) {
  const stateDir = resolveStateDir(flags);
  const vault = await openVaultUnlocked(flags);
  try {
    const cred = vault.get(name);
    if (!cred || cred.type !== "browser-profile") {
      const e = new Error(`no browser-profile named '${name}' — run \`login --name ${name}\` first`);
      e.code = "NO_PROFILE";
      throw e;
    }
    if (!(await sealedProfileExists(stateDir, cred.profileFile))) {
      const e = new Error(`sealed profile for '${name}' is missing — re-run \`login --name ${name}\``);
      e.code = "NO_PROFILE";
      throw e;
    }

    const work = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-bwork-"));
    try {
      await unsealProfile({ stateDir, file: cred.profileFile, dekHex: cred.dek, destDir: work });
      const useHeadless = headless != null ? headless : cred.headless !== false;
      const ctx = await launchContext({ profileDir: work, headless: useHeadless });
      let result;
      try {
        result = await action(ctx, cred);
      } finally {
        await ctx.close();
      }
      // Re-seal to capture the refreshed session (rotated cookies), then persist.
      await sealProfile({ stateDir, file: cred.profileFile, dekHex: cred.dek, sourceDir: work });
      vault.add({ ...cred, lastSyncedAt: Date.now() });
      await vault.save();
      return result;
    } finally {
      await fs.rm(work, { recursive: true, force: true });
    }
  } finally {
    vault.lock();
  }
}

// ─── Commands ─────────────────────────────────────────────────────────────────────

async function cmdLogin(flags) {
  const name = String(flags.name || "default");
  const stateDir = resolveStateDir(flags);
  const file = `${name}.tar.enc`;
  const startUrl = flags.url ? String(flags.url) : "about:blank";
  const headlessDefault = flags["headed-default"] === true ? false : true;

  let vault;
  try {
    vault = await openVaultUnlocked(flags);
  } catch (err) {
    return handleErr(err);
  }

  try {
    const work = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-blogin-"));
    try {
      const ctx = await launchContext({ profileDir: work, headless: false });
      stderr(
        `A browser window opened${flags.url ? " at " + startUrl : ""}. ` +
          "Sign in, then CLOSE the window when you're done.",
      );
      const page = ctx.pages()[0] || (await ctx.newPage());
      try {
        await page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
      } catch {
        /* about:blank or slow page — fine, the user drives from here */
      }
      await waitForUserClose(ctx, Number(flags["timeout-sec"] || 600) * 1000);
      try {
        await ctx.close();
      } catch {
        /* already closed by the user */
      }

      const dek = newDek();
      const { bytes } = await sealProfile({ stateDir, file, dekHex: dek, sourceDir: work });
      vault.add({
        name,
        type: "browser-profile",
        domains: ["*"],
        description: flags.description
          ? String(flags.description)
          : "Sealed browser profile (agent-id-browser)",
        dek,
        profileFile: file,
        headless: headlessDefault,
        // The DEK is generated in-vault and must never be shown to the agent —
        // `vault show` redacts sealed fields (incl. dek) for exportable:false.
        exportable: false,
        ...(flags.account ? { account: String(flags.account) } : {}),
        lastSyncedAt: Date.now(),
      });
      await vault.save();
      outputJson({
        ok: true,
        name,
        profileFile: file,
        sealedBytes: bytes,
        account: flags.account ? String(flags.account) : null,
        headlessDefault,
        message: "Profile sealed in the vault. Subsequent reads run headless by default.",
      });
    } finally {
      await fs.rm(work, { recursive: true, force: true });
    }
  } catch (err) {
    handleErr(err);
  } finally {
    vault.lock();
  }
}

async function cmdRead(flags) {
  const name = String(flags.name || "default");
  if (!flags.url) return outputError("--url is required");
  const url = String(flags.url);
  const maxChars = Number(flags["max-chars"] || 4000);

  try {
    const out = await withProfile({
      flags,
      name,
      headless: resolveHeadless(flags),
      action: async (ctx) => {
        const page = ctx.pages()[0] || (await ctx.newPage());
        const resp = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
        await page.waitForTimeout(1500);
        const finalUrl = page.url();
        const title = await page.title().catch(() => "");
        let text = "";
        try {
          text = await page.evaluate(() => (document.body ? document.body.innerText : ""));
        } catch {
          /* page navigated/destroyed — leave text empty */
        }
        const httpStatus = resp ? resp.status() : null;
        return {
          httpStatus,
          finalUrl,
          title,
          loggedOut: looksLoggedOut({ finalUrl, bodyText: text, httpStatus }),
          text: String(text).slice(0, maxChars),
        };
      },
    });
    if (out.loggedOut) {
      outputJson({
        ok: true,
        sessionExpired: true,
        action: "re_login",
        message: `Session looks logged out (landed on ${out.finalUrl}). Re-run \`login --name ${name}\`.`,
        ...out,
      });
    } else {
      outputJson({ ok: true, sessionExpired: false, ...out });
    }
  } catch (err) {
    handleErr(err);
  }
}

async function cmdFetch(flags) {
  const name = String(flags.name || "default");
  if (!flags.url) return outputError("--url is required");
  const url = String(flags.url);
  const maxChars = Number(flags["max-chars"] || 8000);

  try {
    const out = await withProfile({
      flags,
      name,
      headless: resolveHeadless(flags),
      action: async (ctx) => {
        const resp = await ctx.request.get(url, { timeout: 30000 });
        const httpStatus = resp.status();
        let body = "";
        try {
          body = await resp.text();
        } catch {
          /* binary or empty body */
        }
        return {
          httpStatus,
          finalUrl: resp.url(),
          loggedOut: looksLoggedOut({ finalUrl: resp.url(), bodyText: body, httpStatus }),
          body: String(body).slice(0, maxChars),
        };
      },
    });
    if (out.loggedOut) {
      outputJson({
        ok: true,
        sessionExpired: true,
        action: "re_login",
        message: `Request looks logged out (status ${out.httpStatus}). Re-run \`login --name ${name}\`.`,
        ...out,
      });
    } else {
      outputJson({ ok: true, sessionExpired: false, ...out });
    }
  } catch (err) {
    handleErr(err);
  }
}

async function cmdStatus(flags) {
  const stateDir = resolveStateDir(flags);
  const only = flags.name ? String(flags.name) : null;
  let vault;
  try {
    // Don't drive an Alien-app prompt just to report status — agent-key/passphrase only.
    vault = await openVaultUnlocked(flags, { allowOwnerApproval: false });
  } catch (err) {
    if (err.code === "VAULT_LOCKED") {
      return outputJson({
        ok: true,
        unlocked: false,
        message:
          "Vault is locked — unlock via agent-key, --passphrase-file, or owner-approval " +
          "(the Alien app) when you run a browser command.",
      });
    }
    return handleErr(err);
  }
  try {
    const meta = vault.list().filter((c) => c.type === "browser-profile");
    const profiles = [];
    for (const m of meta) {
      if (only && m.name !== only) continue;
      const cred = vault.get(m.name);
      profiles.push({
        name: m.name,
        account: m.account || null,
        headlessDefault: m.headless !== false,
        sealed: await sealedProfileExists(stateDir, cred.profileFile),
        lastSyncedAt: cred.lastSyncedAt || null,
      });
    }
    outputJson({ ok: true, unlocked: true, profiles });
  } catch (err) {
    handleErr(err);
  } finally {
    vault.lock();
  }
}

// ─── Interactive session: open / close / actions ─────────────────────────────────

async function cmdOpen(flags) {
  const name = String(flags.name || "default");
  const stateDir = resolveStateDir(flags);
  let vault;
  try {
    vault = await openVaultUnlocked(flags);
  } catch (err) {
    return handleErr(err);
  }
  let dekHex;
  let profileFile;
  let headlessDefault;
  try {
    const cred = vault.get(name);
    if (!cred || cred.type !== "browser-profile") {
      const e = new Error(`no browser-profile named '${name}' — run \`login --name ${name}\` first`);
      e.code = "NO_PROFILE";
      throw e;
    }
    if (!(await sealedProfileExists(stateDir, cred.profileFile))) {
      const e = new Error(`sealed profile for '${name}' missing — re-run \`login --name ${name}\``);
      e.code = "NO_PROFILE";
      throw e;
    }
    dekHex = cred.dek;
    profileFile = cred.profileFile;
    headlessDefault = cred.headless !== false;
  } catch (err) {
    vault.lock();
    return handleErr(err);
  }
  vault.lock(); // we hold dek + profileFile; don't keep the vault open for the session

  const headless = resolveHeadless(flags) ?? headlessDefault;
  const workDir = path.join(stateDir, "browser-sessions", `${name}.work`);
  try {
    await fs.rm(workDir, { recursive: true, force: true });
    await unsealProfile({ stateDir, file: profileFile, dekHex, destDir: workDir });
    stderr(
      `Session '${name}' starting (${headless ? "headless" : "headed"}). Keep this process ` +
        `running (background it); issue actions, then \`close --name ${name}\`.`,
    );
    await runSession({ stateDir, name, headless, dekHex, profileFile, workDir }); // blocks until close
  } catch (err) {
    await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    handleErr(err);
  }
}

async function cmdClose(flags) {
  const stateDir = resolveStateDir(flags);
  const name = String(flags.name || "default");
  try {
    const r = await callSession(stateDir, name, "close", {});
    outputJson({ ok: true, closed: name, ...r });
  } catch (err) {
    if (err.code === "NO_SESSION") {
      return outputJson({ ok: true, closed: name, note: "no open session (already closed)" });
    }
    handleErr(err);
  }
}

async function cmdSessions(flags) {
  const stateDir = resolveStateDir(flags);
  const dir = path.join(stateDir, "browser-sessions");
  const sessions = [];
  let files = [];
  try {
    files = (await fs.readdir(dir)).filter((f) => f.endsWith(".json"));
  } catch {
    /* none */
  }
  for (const f of files) {
    try {
      const info = JSON.parse(await fs.readFile(path.join(dir, f), "utf8"));
      sessions.push({ name: f.replace(/\.json$/, ""), headless: info.headless, pid: info.pid, startedAt: info.startedAt });
    } catch {
      /* skip */
    }
  }
  outputJson({ ok: true, sessions });
}

// Thin client for an action against a running session. `map` turns flags into
// the action's params. The server's JSON reply is passed straight through.
function actionCmd(action, map) {
  return async (flags) => {
    const stateDir = resolveStateDir(flags);
    const name = String(flags.name || "default");
    try {
      const params = map ? map(flags) : {};
      const r = await callSession(stateDir, name, action, params);
      outputJson(r);
      if (r && r.ok === false) process.exitCode = 1;
    } catch (err) {
      handleErr(err);
    }
  };
}

const requireUrl = (f) => {
  if (!f.url) throw new Error("--url is required");
  return String(f.url);
};
const csv = (v) => (v == null ? undefined : String(v).split(",").map((s) => s.trim()).filter(Boolean));

runCli({
  commands: {
    login: cmdLogin,
    read: cmdRead,
    fetch: cmdFetch,
    status: cmdStatus,
    open: cmdOpen,
    close: cmdClose,
    sessions: cmdSessions,
    snapshot: actionCmd("snapshot"),
    navigate: actionCmd("navigate", (f) => ({ url: requireUrl(f) })),
    back: actionCmd("back"),
    "page-text": actionCmd("text", (f) => ({ maxChars: f["max-chars"] })),
    click: actionCmd("click", (f) => ({ ref: f.ref })),
    type: actionCmd("type", (f) => ({ ref: f.ref, text: f.text ?? "", submit: f.submit === true })),
    fill: actionCmd("fill", (f) => ({ fields: JSON.parse(f.fields || "[]") })),
    select: actionCmd("select", (f) => ({ ref: f.ref, values: csv(f.values) })),
    press: actionCmd("press", (f) => ({ key: f.key, ref: f.ref })),
    hover: actionCmd("hover", (f) => ({ ref: f.ref })),
    scroll: actionCmd("scroll", (f) => ({ dx: f.dx, dy: f.dy })),
    screenshot: actionCmd("screenshot", (f) => ({ path: f.path, fullPage: f.full === true || f.fullPage === true })),
    eval: actionCmd("eval", (f) => ({ expression: f.js ?? f.expression })),
    wait: actionCmd("wait", (f) => ({ text: f.text, ms: f.ms })),
  },
  printHelp: () =>
    stderr(
      "agent-id-browser — universal browser; logged-in profile sealed in the vault\n\n" +
        "Setup / one-shot:\n" +
        "  login   --name N [--url START] [--account LABEL] [--headed-default]\n" +
        "          one-time HEADED login; seals the profile into the vault\n" +
        "  read    --name N --url URL [--headed] [--max-chars K]\n" +
        "          one-shot: navigate (headless) → page text + final URL + sessionExpired\n" +
        "  fetch   --name N --url URL [--max-chars K]\n" +
        "          one-shot authenticated HTTP GET via the session (API / feed)\n" +
        "  status  [--name N]      list sealed profiles\n\n" +
        "Interactive session (fine-grained control):\n" +
        "  open    --name N [--headed]   start a persistent session (run in background)\n" +
        "  snapshot --name N             accessibility tree with element refs (eN)\n" +
        "  click   --name N --ref eN\n" +
        "  type    --name N --ref eN --text T [--submit]\n" +
        "  fill    --name N --fields '[{\"ref\":\"e1\",\"value\":\"..\"}]'\n" +
        "  select  --name N --ref eN --values a,b      press --name N --key Enter [--ref eN]\n" +
        "  hover   --name N --ref eN                   scroll --name N [--dy 600]\n" +
        "  navigate --name N --url URL                 back --name N\n" +
        "  page-text --name N [--max-chars K]          wait --name N [--text T | --ms N]\n" +
        "  screenshot --name N [--path P] [--full]     eval --name N --js 'EXPR'\n" +
        "  sessions                list open sessions   close --name N\n\n" +
        "Unlock: agent-key (auto) | --passphrase-file F | --passphrase-env V |\n" +
        "        owner-approval (approve in the Alien app; --no-owner-approval to skip).\n" +
        "If none works, commands return VAULT_LOCKED — ask the owner to unlock, don't retry.\n" +
        "patchright auto-installs into the plugin data dir on first session (drives your\n" +
        "installed Chrome via channel=chrome; pass --plugin-data <dir> when not run by a hook).",
    ),
});
