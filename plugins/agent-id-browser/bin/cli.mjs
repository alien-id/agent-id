#!/usr/bin/env node

// Alien Agent ID — Browser plugin CLI.
//
// A universal browser the agent can drive, with an anonymous-or-logged-in
// profile sealed in the vault. By DEFAULT every command shares ONE session
// ("main") — public browsing auto-creates it; sign into
// Google once and every "Sign in with Google" site reuses it. `login` is ADDITIVE:
// re-run it to add more sites to the same session. Pass --name to opt into a
// SEPARATE, isolated session (a second account, a sandbox). After a HEADED login
// the agent drives the browser HEADLESS by default (no window) to read/fetch.
//
//   login  [--name N] [--url START] [--account LABEL] [--fresh]
//          opens a real window with the session loaded; sign in, close it; the
//          session is (re)sealed. --fresh discards the existing session, starts clean.
//   read   [--name N] --url URL [--headed] [--max-chars K]
//          navigate (headless by default) and return the page's text + final URL.
//   fetch  [--name N] --url URL [--headed] [--max-chars K]
//          authenticated HTTP GET via the session (e.g. an API or Atom feed).
//   status [--name N]   list sealed sessions; reports unlocked / sealed / account.
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
} from "@alien-id/agent-id-core/lib/cli-runtime.mjs";
import { openVault, loadAgentPrivateKey } from "@alien-id/agent-id-vault/lib/vault.mjs";

import {
  newDek,
  sealProfile,
  unsealProfile,
  sealedProfileExists,
  ensureAnonymousDefaultProfile,
} from "../lib/profile-store.mjs";
import { launchContext } from "../lib/launch.mjs";
import { DEFAULT_PROFILE, loginHint, noProfileHint, profileName } from "../lib/hints.mjs";
import { autoLogin } from "../lib/auto-login.mjs";
import { looksLoggedOut } from "../lib/session.mjs";
import { runSession, callSession } from "../lib/session-server.mjs";
import { hasOwnerApproval, unlockViaOwnerApproval } from "../lib/unlock.mjs";
import {
  ACCESS_LEVELS,
  effectiveAccess,
  isAccessRelaxation,
  strictestAccess,
} from "@alien-id/agent-id-vault/lib/access.mjs";
import {
  applyAccessGuard,
  contextOptionsForAccess,
  guardDecision,
} from "../lib/access-guard.mjs";

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

// The default browser session is ONE shared cookie jar ("main") so logins — and
// especially shared SSO like "Sign in with Google" — carry across sites. Pass
// --name to opt into a separate, isolated session (a second account, a sandbox).

// Suggest the right login command: bare `login` for the shared default, `--name` otherwise.

// ─── Profile lifecycle: unseal → run → reseal → wipe ──────────────────────────────

async function withProfile({ flags, name, headless, action }) {
  const stateDir = resolveStateDir(flags);
  const vault = await openVaultUnlocked(flags);
  try {
    const cred = await ensureAnonymousDefaultProfile({ vault, stateDir, name });
    if (!cred || cred.type !== "browser-profile") {
      const e = new Error(`no browser-profile named '${name}' — ${noProfileHint(name)}`);
      e.code = "NO_PROFILE";
      throw e;
    }
    if (!(await sealedProfileExists(stateDir, cred.profileFile))) {
      const e = new Error(`sealed profile for '${name}' is missing — re-run ${loginHint(name)}`);
      e.code = "NO_PROFILE";
      throw e;
    }

    const work = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-bwork-"));
    try {
      await unsealProfile({ stateDir, file: cred.profileFile, dekHex: cred.dek, destDir: work });
      const useHeadless = headless != null ? headless : cred.headless !== false;
      const ctx = await launchContext({
        profileDir: work,
        headless: useHeadless,
        contextOptions: contextOptionsForAccess(cred),
      });
      // Read-only profile → network gate on everything this context does.
      await applyAccessGuard(ctx, cred, { log: (m) => stderr(m) });
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
  const name = profileName(flags.name);
  const stateDir = resolveStateDir(flags);
  const startUrl = flags.url ? String(flags.url) : "about:blank";
  const access = flags.access != null ? String(flags.access) : null;
  if (access && !ACCESS_LEVELS.includes(access)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }

  let vault;
  try {
    vault = await openVaultUnlocked(flags);
  } catch (err) {
    return handleErr(err);
  }

  try {
    const work = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-blogin-"));
    try {
      // ADDITIVE login: resume the existing sealed session so logins ACCUMULATE in
      // one cookie jar — sign into Google once and every "Sign in with Google" site
      // reuses it. `--fresh` discards the existing session and starts clean.
      const existing = vault.get(name);
      const resuming =
        flags.fresh !== true &&
        existing &&
        existing.type === "browser-profile" &&
        (await sealedProfileExists(stateDir, existing.profileFile));
      if (resuming) {
        await unsealProfile({ stateDir, file: existing.profileFile, dekHex: existing.dek, destDir: work });
      }
      const reuse = resuming ? existing : null;
      // A login can create a restricted session or tighten one — never widen
      // one. Widening is the owner's call: `agent-id-vault set-access`.
      if (reuse && access && isAccessRelaxation(reuse, { ...reuse, access })) {
        return outputError(
          `session '${name}' has access level '${effectiveAccess(reuse)}' — a re-login cannot ` +
            `widen it to '${access}'. The owner can: agent-id-vault set-access --name ${name} --access ${access}`,
        );
      }
      const file = reuse ? reuse.profileFile : `${name}.tar.enc`;
      const dek = reuse ? reuse.dek : newDek();
      const account = flags.account ? String(flags.account) : reuse?.account || null;
      const headlessDefault =
        flags["headed-default"] === true ? false : reuse ? reuse.headless !== false : true;

      const ctx = await launchContext({ profileDir: work, headless: false });
      stderr(
        resuming
          ? `A browser opened with your '${name}' session loaded${flags.url ? " at " + startUrl : ""}. ` +
              "Sign into the new site (your existing logins are kept), then CLOSE the window."
          : `A browser window opened${flags.url ? " at " + startUrl : ""}. ` +
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

      const { bytes } = await sealProfile({ stateDir, file, dekHex: dek, sourceDir: work });
      vault.add({
        ...(reuse || {}),
        name,
        type: "browser-profile",
        domains: ["*"],
        description: flags.description
          ? String(flags.description)
          : reuse?.description || "Sealed browser profile (agent-id-browser)",
        dek,
        profileFile: file,
        headless: headlessDefault,
        // The DEK is generated in-vault and must never be shown to the agent —
        // `vault show` redacts sealed fields (incl. dek) for exportable:false.
        exportable: false,
        // Tighten (or set on a fresh profile); the reuse spread already carries
        // an existing restriction forward, and widening was refused above.
        ...(access ? { access } : {}),
        ...(account ? { account } : {}),
        lastSyncedAt: Date.now(),
      });
      await vault.save();
      outputJson({
        ok: true,
        name,
        profileFile: file,
        sealedBytes: bytes,
        resumed: !!resuming,
        account,
        access: access || (reuse ? effectiveAccess(reuse) : "rw"),
        headlessDefault,
        message: resuming
          ? `Added to your existing '${name}' session — other logins kept.`
          : `Session '${name}' sealed. Reuse it for every site (shared SSO like Google carries across); run \`login\` again to add more. Reads run headless by default.`,
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

// auto-login: drive the sealed browser through a service login using a stored
// `login` credential, answering 2FA from a stored seed or via the secure prompt,
// then seal the resulting session into a browser-profile so read/fetch/open reuse
// it. For places where a full desktop browser isn't on hand (the browser can run
// headless/remote; the human only touches the abstracted secure-prompt surface).
async function cmdAutoLogin(flags) {
  const credName = flags.cred ? String(flags.cred) : null;
  if (!credName) {
    return outputError("--cred <LOGIN_CRED> is required (the name of a `login` credential)");
  }
  const requestedAccess = flags.access != null ? String(flags.access) : null;
  if (requestedAccess && !ACCESS_LEVELS.includes(requestedAccess)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }
  const stateDir = resolveStateDir(flags);

  let vault;
  try {
    vault = await openVaultUnlocked(flags);
  } catch (err) {
    return handleErr(err);
  }

  try {
    const cred = vault.get(credName);
    if (!cred || cred.type !== "login") {
      const e = new Error(
        `no 'login' credential named '${credName}' — add one with ` +
          "`agent-id-vault add --type login --login-url … --form`",
      );
      e.code = "NO_PROFILE";
      throw e;
    }
    if (!cred.loginUrl) {
      return outputError(`login '${credName}' has no loginUrl — set one so auto-login knows where to start`);
    }

    const targetProfile = profileName(flags.name || cred.profile);
    // A login and its sealed browser-profile are two records in ONE name
    // namespace — sealing into the login's own name would overwrite it.
    if (targetProfile === credName) {
      return outputError(
        `target profile '${targetProfile}' must differ from the login credential '${credName}' ` +
          "(they share the vault namespace) — pass --name <other> or set the cred's `profile`",
      );
    }
    const existing = vault.get(targetProfile);
    const reuse = existing && existing.type === "browser-profile" ? existing : null;

    // The session's access level is the STRICTEST of: the login credential's
    // (a read-only credential can only mint read-only sessions), the existing
    // profile's (a re-login never widens), and the requested flag. An explicit
    // request the ceiling forbids is an error, not a silent clamp.
    const ceiling = effectiveAccess(cred);
    if (requestedAccess === "rw" && ceiling === "ro") {
      return outputError(
        `login credential '${credName}' is read-only — sessions minted from it cannot be 'rw'. ` +
          `The owner can widen it: agent-id-vault set-access --name ${credName} --access rw`,
      );
    }
    if (reuse && requestedAccess && isAccessRelaxation(reuse, { ...reuse, access: requestedAccess })) {
      return outputError(
        `session '${targetProfile}' has access level '${effectiveAccess(reuse)}' — auto-login cannot ` +
          `widen it. The owner can: agent-id-vault set-access --name ${targetProfile} --access ${requestedAccess}`,
      );
    }
    const sessionAccess = strictestAccess(
      strictestAccess(requestedAccess || "rw", ceiling),
      reuse ? effectiveAccess(reuse) : "rw",
    );

    const file = reuse ? reuse.profileFile : `${targetProfile}.tar.enc`;
    const dek = reuse ? reuse.dek : newDek();
    const headless = resolveHeadless(flags) ?? true;

    const work = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-autologin-"));
    try {
      const ctx = await launchContext({ profileDir: work, headless });
      let result;
      try {
        const page = ctx.pages()[0] || (await ctx.newPage());
        result = await autoLogin({ page, cred, env: process.env, log: (m) => stderr(m) });
      } finally {
        // Close so the context flushes cookies/storage to the work dir before sealing.
        await ctx.close().catch(() => {});
      }

      if (!result || !result.ok) {
        const outcome = result ? result.outcome : "unknown";
        // A bot-block wall (e.g. Reddit's "blocked by network security") can't be
        // cleared by an automated credential submission — the login handshake is
        // exactly where anti-automation bites. A human driving a headed login
        // clears it and the session seals with the SAME access level.
        const message =
          outcome === "blocked"
            ? `Auto-login for '${credName}' was blocked by an anti-automation wall (bot ` +
              "challenge / network-security block). This hits the login handshake specifically; " +
              `sign in yourself once with headed \`login --name ${targetProfile}` +
              `${requestedAccess ? ` --access ${requestedAccess}` : ""}\` — it seals the same session.`
            : `Auto-login for '${credName}' did not complete (${outcome}). ` +
              "Verify the credentials / loginUrl, add a `recipe` to the credential, or bootstrap " +
              `once with headed \`login --name ${targetProfile}\`.`;
        outputJson({
          ok: false,
          error: "AUTO_LOGIN_FAILED",
          outcome,
          finalUrl: result ? result.finalUrl : null,
          message,
        });
        process.exitCode = 1;
        return;
      }

      // Seal the authenticated session (same upsert/seal path as `login`).
      const { bytes } = await sealProfile({ stateDir, file, dekHex: dek, sourceDir: work });
      vault.add({
        ...(reuse || {}),
        name: targetProfile,
        type: "browser-profile",
        domains: ["*"],
        description: reuse?.description || `Auto-login session for '${credName}' (agent-id-browser)`,
        dek,
        profileFile: file,
        headless: reuse ? reuse.headless !== false : true,
        exportable: false,
        ...(sessionAccess !== "rw" ? { access: sessionAccess } : {}),
        // A fresh profile inherits the login credential's rules; an existing
        // profile keeps its own (carried by the reuse spread).
        ...(!reuse && Array.isArray(cred.accessRules) ? { accessRules: cred.accessRules } : {}),
        ...(reuse?.account || cred.username ? { account: reuse?.account || cred.username } : {}),
        lastSyncedAt: Date.now(),
      });
      vault.touchLastUsed(credName);
      await vault.save();
      outputJson({
        ok: true,
        cred: credName,
        profile: targetProfile,
        outcome: result.outcome,
        finalUrl: result.finalUrl,
        access: sessionAccess,
        sealedBytes: bytes,
        message: `Logged in and sealed session '${targetProfile}'. Reuse it: \`read --name ${targetProfile} --url …\`.`,
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
  const name = profileName(flags.name);
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
        message: `Session looks logged out (landed on ${out.finalUrl}). Re-run ${loginHint(name)}.`,
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
  const name = profileName(flags.name);
  if (!flags.url) return outputError("--url is required");
  const url = String(flags.url);
  const maxChars = Number(flags["max-chars"] || 8000);

  try {
    const out = await withProfile({
      flags,
      name,
      headless: resolveHeadless(flags),
      action: async (ctx, cred) => {
        // ctx.request bypasses route interception — check the policy directly.
        const decision = guardDecision(cred, { method: "GET", url, postData: null });
        if (!decision.allowed) {
          throw new Error(
            `access level '${effectiveAccess(cred)}' blocks GET ${url} (${decision.reason})`,
          );
        }
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
        message: `Request looks logged out (status ${out.httpStatus}). Re-run ${loginHint(name)}.`,
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
  const only = flags.name ? profileName(flags.name) : null;
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
        access: effectiveAccess(cred),
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
  const name = profileName(flags.name);
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
  let policy = null;
  try {
    const cred = await ensureAnonymousDefaultProfile({ vault, stateDir, name });
    if (!cred || cred.type !== "browser-profile") {
      const e = new Error(`no browser-profile named '${name}' — ${noProfileHint(name)}`);
      e.code = "NO_PROFILE";
      throw e;
    }
    if (!(await sealedProfileExists(stateDir, cred.profileFile))) {
      const e = new Error(`sealed profile for '${name}' missing — re-run ${loginHint(name)}`);
      e.code = "NO_PROFILE";
      throw e;
    }
    dekHex = cred.dek;
    profileFile = cred.profileFile;
    headlessDefault = cred.headless !== false;
    if (cred.access != null || cred.accessRules != null) {
      policy = {
        ...(cred.access != null ? { access: cred.access } : {}),
        ...(cred.accessRules != null ? { accessRules: cred.accessRules } : {}),
      };
    }
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
      `Session '${name}' starting (${headless ? "headless" : "headed"}` +
        `${policy && effectiveAccess(policy) === "ro" ? ", READ-ONLY" : ""}). Keep this process ` +
        `running (background it); issue actions, then \`close --name ${name}\`.`,
    );
    await runSession({ stateDir, name, headless, dekHex, profileFile, workDir, policy }); // blocks until close
  } catch (err) {
    await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    handleErr(err);
  }
}

async function cmdClose(flags) {
  const stateDir = resolveStateDir(flags);
  const name = profileName(flags.name);
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
function actionCmd(action, map, timeoutMs) {
  return async (flags) => {
    const stateDir = resolveStateDir(flags);
    const name = profileName(flags.name);
    try {
      const params = map ? map(flags) : {};
      const r = await callSession(stateDir, name, action, params, timeoutMs);
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
// "x0,y0,x1,y1" → [n,n,n,n] for screenshot --region / zoom.
const region = (v) => (v == null ? undefined : String(v).split(",").map((s) => Number(s.trim())));

runCli({
  commands: {
    login: cmdLogin,
    "auto-login": cmdAutoLogin,
    read: cmdRead,
    fetch: cmdFetch,
    status: cmdStatus,
    open: cmdOpen,
    close: cmdClose,
    sessions: cmdSessions,
    snapshot: actionCmd("snapshot"),
    "form-inspect": actionCmd("form-inspect"),
    "form-fill": actionCmd("form-fill", (f) => JSON.parse(f.spec || "{}"), 120000),
    navigate: actionCmd("navigate", (f) => ({ url: requireUrl(f) })),
    back: actionCmd("back"),
    "page-text": actionCmd("text", (f) => ({ maxChars: f["max-chars"] })),
    click: actionCmd("click", (f) => ({ ref: f.ref })),
    dblclick: actionCmd("dblclick", (f) => ({ ref: f.ref })),
    check: actionCmd("check", (f) => ({ ref: f.ref })),
    uncheck: actionCmd("uncheck", (f) => ({ ref: f.ref })),
    drag: actionCmd("drag", (f) => ({ ref: f.ref, to: f.to })),
    upload: actionCmd("upload", (f) => ({ ref: f.ref, files: csv(f.files) })),
    type: actionCmd("type", (f) => ({ ref: f.ref, text: f.text ?? "", submit: f.submit === true })),
    fill: actionCmd("fill", (f) => ({ fields: JSON.parse(f.fields || "[]") })),
    // Secret injection by reference: the agent picks the element (ref) from a
    // snapshot; the vault supplies the value, which never returns to the agent.
    "fill-secret": actionCmd("fill-secret", (f) => ({ ref: f.ref, cred: f.cred, submit: f.submit === true })),
    "fill-otp": actionCmd("fill-otp", (f) => ({ ref: f.ref, cred: f.cred, submit: f.submit !== false }), 360000),
    select: actionCmd("select", (f) => ({ ref: f.ref, values: csv(f.values) })),
    press: actionCmd("press", (f) => ({ key: f.key, ref: f.ref })),
    hover: actionCmd("hover", (f) => ({ ref: f.ref })),
    scroll: actionCmd("scroll", (f) => ({ dx: f.dx, dy: f.dy })),
    // Coordinate (vision) actions — pair with `screenshot` for the hybrid path.
    "click-xy": actionCmd("click-xy", (f) => ({ x: f.x, y: f.y, button: f.button, double: f.double === true, css: f.css === true })),
    "move-xy": actionCmd("move-xy", (f) => ({ x: f.x, y: f.y, css: f.css === true })),
    "drag-xy": actionCmd("drag-xy", (f) => ({ x: f.x, y: f.y, tox: f.tox, toy: f.toy, css: f.css === true })),
    "scroll-xy": actionCmd("scroll-xy", (f) => ({ x: f.x, y: f.y, dx: f.dx, dy: f.dy, css: f.css === true })),
    "type-text": actionCmd("type-text", (f) => ({ text: f.text ?? "", submit: f.submit === true })),
    "fill-text": actionCmd("fill-text", (f) => ({ text: f.text ?? "", submit: f.submit === true })),
    "probe-xy": actionCmd("probe-xy", (f) => ({ x: f.x, y: f.y, css: f.css === true })),
    resize: actionCmd("resize", (f) => ({ width: f.width, height: f.height })),
    screenshot: actionCmd("screenshot", (f) => ({ path: f.path, fullPage: f.full === true || f.fullPage === true, region: region(f.region) })),
    // zoom = a cropped, closer screenshot of a UI region (image px x0,y0,x1,y1).
    zoom: actionCmd("screenshot", (f) => ({ path: f.path, region: region(f.region), requireRegion: true, css: f.css === true })),
    eval: actionCmd("eval", (f) => ({ expression: f.js ?? f.expression })),
    wait: actionCmd("wait", (f) => ({ text: f.text, ms: f.ms, url: f.url, load: f.load })),
    get: actionCmd("get", (f) => ({ ref: f.ref, what: f.what, attr: f.attr, maxChars: f["max-chars"] })),
    is: actionCmd("is", (f) => ({ ref: f.ref, what: f.what })),
    tabs: actionCmd("tabs"),
    "tab-new": actionCmd("tab-new", (f) => ({ url: f.url }), 45000),
    "tab-switch": actionCmd("tab-switch", (f) => ({ index: f.index })),
    "tab-close": actionCmd("tab-close", (f) => ({ index: f.index })),
    dialog: actionCmd("dialog", (f) => ({ mode: f.mode, text: f.text })),
    downloads: actionCmd("downloads", (f) => ({ max: f.max })),
    console: actionCmd("console", (f) => ({ level: f.level, max: f.max })),
    cookies: actionCmd("cookies", (f) => ({ url: f.url })),
    batch: actionCmd("batch", (f) => ({ actions: JSON.parse(f.actions || "[]"), delay: f.delay }), 320000),
  },
  printHelp: () =>
    stderr(
      "agent-id-browser — universal browser; one shared logged-in session in the vault\n\n" +
        "Sessions: every command shares ONE session ('main') by default — sign into\n" +
        "Google once, reuse it everywhere. `login` is ADDITIVE (re-run to add sites).\n" +
        "Use --name to open a SEPARATE isolated session; --fresh discards & restarts one.\n\n" +
        "Setup / one-shot ([--name N] optional; defaults to the shared 'main' session):\n" +
        "  login   [--name N] [--url START] [--account LABEL] [--fresh] [--access ro|rw]\n" +
        "          HEADED login; (re)seals the session into the vault (additive)\n" +
        "  auto-login --cred LOGIN [--name N] [--headed] [--access ro|rw]\n" +
        "          drive a service login from a vault `login` credential (username/\n" +
        "          password + 2FA via stored seed or the secure prompt); seals the\n" +
        "          session into profile N (default the cred's `profile`, else 'main')\n" +
        "          --access ro seals a READ-ONLY session: every request the page\n" +
        "          makes is classified in the session process; writes are blocked\n" +
        "          at the wire (GET/HEAD/OPTIONS + GraphQL-query/JMAP-get/JSON-RPC\n" +
        "          reads pass), WebSockets/service-workers are disabled, and\n" +
        "          eval/fill-secret/fill-otp are refused. A ro login credential\n" +
        "          only mints ro sessions; re-logins can tighten but never widen\n" +
        "          (the owner widens via `agent-id-vault set-access`).\n" +
        "  read    [--name N] --url URL [--headed] [--max-chars K]\n" +
        "          one-shot: navigate (headless) → page text + final URL + sessionExpired\n" +
        "  fetch   [--name N] --url URL [--max-chars K]\n" +
        "          one-shot authenticated HTTP GET via the session (API / feed)\n" +
        "  status  [--name N]      list sealed sessions\n\n" +
        "Interactive session (--name optional; defaults to 'main'):\n" +
        "  open    --name N [--headed]   start a persistent session (run in background);\n" +
        "          missing default 'main' auto-creates as an anonymous L0 profile\n" +
        "  snapshot --name N             accessibility tree with element refs; iframe\n" +
        "          elements get frame-prefixed refs (f1e3); reports open tabs when >1\n" +
        "  form-inspect --name N           compact form controls + labels/types/requirements\n" +
        "  form-fill --name N --spec '{\"fields\":[{\"ref\":\"e1\",\"value\":\"A\"}],\n" +
        "          \"checks\":[{\"ref\":\"e2\",\"checked\":true}],\"selects\":[...],\n" +
        "          \"uploads\":[{\"ref\":\"e3\",\"files\":[\"/a.pdf\"]}]}'\n" +
        "          atomic fast fill with per-control verification; max 50 controls\n" +
        "  click   --name N --ref eN                   dblclick --name N --ref eN\n" +
        "  check   --name N --ref eN                   uncheck  --name N --ref eN\n" +
        "  type    --name N --ref eN --text T [--submit]\n" +
        "  fill    --name N --fields '[{\"ref\":\"e1\",\"value\":\"..\"}]'\n" +
        "  fill-secret --name N --ref eN --cred NAME.field [--submit]\n" +
        "          inject a vaulted secret into the ref'd field (agent never sees the value)\n" +
        "  fill-otp    --name N --ref eN --cred NAME\n" +
        "          type the current 2FA code (stored seed, or asked via the secure prompt)\n" +
        "  upload  --name N --ref eN --files /a.pdf[,/b.png]   attach files (file input\n" +
        "          or picker button); refused on read-only sessions\n" +
        "  drag    --name N --ref eN --to eM           same-frame drag & drop\n" +
        "  select  --name N --ref eN --values a,b      press --name N --key Enter [--ref eN]\n" +
        "  hover   --name N --ref eN                   scroll --name N [--dy 600]\n" +
        "  Vision (coordinate) actions — pair with `screenshot`; prefer ref-based\n" +
        "  actions above, use these when the DOM/snapshot is unusable (canvas etc.):\n" +
        "  click-xy --name N --x N --y N [--double] [--button right|middle] [--css]\n" +
        "          click a screenshot PIXEL; coords are auto-converted for retina (dpr)\n" +
        "  move-xy  --name N --x N --y N [--css]        drag-xy --x N --y N --tox N --toy N\n" +
        "  scroll-xy --name N --x N --y N [--dy N] [--dx N]   wheel at a pixel\n" +
        "          (zoom-toward-point on maps; scroll an inner pane). dy>0 = down.\n" +
        "  type-text --name N --text T [--submit]       type into the focused element\n" +
        "          (plaintext only — secrets stay ref-based via fill-secret/fill-otp)\n" +
        "  fill-text --name N --text T [--submit]       paste into the focused element\n" +
        "          (one-shot insert, no per-key events — fast for long text)\n" +
        "  probe-xy --name N --x N --y N                what element is at a pixel\n" +
        "          (tag/role/name/ref — vision→DOM bridge; read-only, ro-safe)\n" +
        "  zoom    --name N --region x0,y0,x1,y1 [--path P]   cropped closer view of\n" +
        "          a UI area (read small icons/text without guessing coords)\n" +
        "  resize  --name N --width W --height H        resize the window (OUTER size;\n" +
        "          the returned `viewport` is the smaller INNER area — use it for coords)\n" +
        "  navigate --name N --url URL                 back --name N\n" +
        "  page-text --name N [--max-chars K]\n" +
        "  wait    --name N [--text T | --url SUBSTR | --load networkidle | --ms N]\n" +
        "  get     --name N [--ref eN] --what text|html|value|attr|url|title [--attr A]\n" +
        "  is      --name N --ref eN --what visible|enabled|checked|editable\n" +
        "  tabs    list open tabs        tab-new [--url U] | tab-switch --index I | tab-close\n" +
        "  dialog  [--mode accept|dismiss [--text T]]   JS-dialog policy + last dialog seen\n" +
        "  downloads               files saved by the page (path + status)\n" +
        "  console [--level error|warn] [--max K]       page console + JS errors (best-\n" +
        "          effort: the stealth driver suppresses most console events)\n" +
        "  cookies [--url U]       cookie metadata (names/domains — values stay sealed)\n" +
        "  batch   --actions '[{\"action\":\"click-xy\",\"params\":{\"x\":9,\"y\":9}},…]' [--delay MS]\n" +
        "          one round trip; any action incl. click-xy/drag-xy; stops on error\n" +
        "  screenshot --name N [--path P] [--full]     PNG + {dpr,viewport,image} for click-xy\n" +
        "  eval    --name N --js 'EXPR'\n" +
        "  sessions                list open sessions   close --name N\n\n" +
        "Unlock: agent-key (auto) | --passphrase-file F | --passphrase-env V |\n" +
        "        owner-approval (approve in the Alien app; --no-owner-approval to skip).\n" +
        "If none works, commands return VAULT_LOCKED — ask the owner to unlock, don't retry.\n" +
        "patchright auto-installs into the plugin data dir on first session (drives your\n" +
        "installed Chrome via channel=chrome; pass --plugin-data <dir> when not run by a hook).",
    ),
});
