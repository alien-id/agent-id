#!/usr/bin/env node

// Alien Agent ID — Browser plugin CLI.
//
// ONE command: `auto-login`. It drives a service's sign-in form in a browser it
// does not own — an agent-browser process reached over its RPC port — using a
// `login` credential from the vault, and answers a 2FA step from a stored TOTP
// seed or by asking the owner over the secure-prompt channel.
//
//   auto-login --cred LOGIN --rpc HOST:PORT
//
// Everything else this CLI used to do — opening sessions, navigating, reading
// pages, snapshots, screenshots, the viewport stream — belongs to whoever drives
// the browser directly now — the RPC port is open to any client. What is left
// here is the one thing that cannot move: the sign-in needs the vault open, and
// the whole point is that the password goes from the vault into the page without
// passing through the agent. This process unlocks the vault, types the secret,
// and never hands it back.
//
// The browser is somebody else's process: this command starts no session it did
// not find and closes none. It leaves the browser signed in, which is the result.
//
// Vault precondition: the vault MUST be unlocked. Unlock order: agent-key slot
// (auto) → passphrase (--passphrase-file / --passphrase-env) → owner-approval
// (the owner approves in the Alien app). If none is available the command emits
// a structured VAULT_LOCKED result — the agent must STOP and ask the owner to
// unlock, never retry blindly.

import fs from "node:fs/promises";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "@alien-id/agent-id-core/lib/cli-runtime.mjs";
import { openVault, loadAgentPrivateKey } from "@alien-id/agent-id-vault/lib/vault.mjs";
import { effectiveAccess } from "@alien-id/agent-id-vault/lib/access.mjs";

import { escalationFor } from "../lib/escalation.mjs";
import { autoLogin } from "../lib/auto-login.mjs";
import { openRpcPage } from "../lib/rpc-page.mjs";
import { hasOwnerApproval, unlockViaOwnerApproval } from "../lib/unlock.mjs";

/**
 * Open the vault, trying every unlock route in order of how little the owner
 * has to do: an agent-key slot needs nothing, a passphrase needs a file or an
 * env var, owner-approval needs them to tap their phone.
 */
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
  if (err.code === "NO_PROFILE") {
    outputJson({ ok: false, error: "NO_PROFILE", message: err.message });
    process.exitCode = 1;
    return;
  }
  if (err.code === "VAULT_NOT_FOUND") return outputError(err.message);
  return outputError(err.message || String(err));
}

/** Where the browser is: named per call, or in the environment for a host that
 *  configures it once. */
function resolveRpc(flags) {
  return ((flags.rpc ? String(flags.rpc) : "") || process.env.AGENT_ID_BROWSER_RPC || "").trim();
}

// auto-login: drive a service's sign-in in the browser at --rpc, using a stored
// `login` credential, answering 2FA from a stored seed or via the secure prompt.
// The browser keeps the session it ends up with — signing in IS the result, and
// its profile is the browser's own business.
async function cmdAutoLogin(flags) {
  const credName = flags.cred ? String(flags.cred) : null;
  if (!credName) {
    return outputError("--cred <LOGIN_CRED> is required (the name of a `login` credential)");
  }
  const rpc = resolveRpc(flags);
  if (!rpc) {
    return outputError(
      "--rpc <host:port> is required (the agent-browser RPC address), or set AGENT_ID_BROWSER_RPC",
    );
  }

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
    // A read-only credential used to mint read-only sessions, enforced at the
    // wire by the session process that owned the browser. This command does not
    // own it: whoever holds the RPC port drives the session afterwards with no
    // such guard, so signing in with a `ro` credential would quietly hand out
    // exactly the access it was restricted from. Refuse instead of pretending.
    if (effectiveAccess(cred) === "ro") {
      return outputError(
        `login credential '${credName}' is read-only, and this browser has no read-only mode to ` +
          "sign in under. The owner can widen it: " +
          `agent-id-vault set-access --name ${credName} --access rw`,
      );
    }

    let page;
    try {
      page = await openRpcPage(rpc);
    } catch (err) {
      // A browser that answers but holds no session is not an unreachable one,
      // and saying so sent the caller looking for a network fault instead of
      // the session they did not open.
      if (err.code === "NO_SESSION") return outputError(err.message);
      return outputError(`the browser at ${rpc} is not reachable: ${err.message}`);
    }

    // What the engine saw, round by round — the failure report carries it so a
    // wrong password is distinguishable from a changed form or a redirect that
    // was never awaited. Never includes a secret.
    const trace = [];
    const result = await autoLogin({
      page,
      cred,
      env: process.env,
      log: (m) => {
        stderr(m);
        trace.push(m);
      },
    });

    if (!result || !result.ok) {
      const outcome = result ? result.outcome : "unknown";
      // `action` is the contract the calling agent branches on: who has to act,
      // and what they can do about it. See lib/escalation.mjs.
      const { action, reason, message } = escalationFor(outcome, { credName, profile: credName });
      outputJson({
        ok: false,
        error: "AUTO_LOGIN_FAILED",
        outcome,
        action,
        reason,
        finalUrl: result ? result.finalUrl : null,
        ...(result && result.errorText ? { pageError: result.errorText } : {}),
        trace,
        message,
      });
      process.exitCode = 1;
      return;
    }

    vault.touchLastUsed(credName);
    await vault.save();
    outputJson({
      ok: true,
      cred: credName,
      outcome: result.outcome,
      finalUrl: result.finalUrl,
      message:
        `Signed in as '${credName}'. The browser holds the session; its own profile keeps the ` +
        "cookies (close it, or flush it, to be sure they are on disk).",
    });
  } catch (err) {
    handleErr(err);
  } finally {
    vault.lock();
  }
}

runCli({
  commands: {
    "auto-login": cmdAutoLogin,
  },
  printHelp: () =>
    stderr(
      "Alien Agent ID — Browser\n\n" +
        "Usage: agent-id-browser auto-login --cred LOGIN --rpc HOST:PORT\n\n" +
        "  Drives the sign-in form of the credential's `loginUrl` in the browser at\n" +
        "  --rpc (an agent-browser RPC port; AGENT_ID_BROWSER_RPC serves as the\n" +
        "  default). The password is read from the vault and typed straight into the\n" +
        "  page — it never reaches the calling agent. A 2FA step is answered from the\n" +
        "  credential's TOTP seed, or by a card raised to the owner at the moment the\n" +
        "  site sends the code.\n\n" +
        "  A recipe on the credential (`agent-id-vault set-recipe`) drives multi-step\n" +
        "  and IdP forms; without one a heuristic fills the identifier and password.\n" +
        "  Every navigation, and every step that types a secret, is confined to the\n" +
        "  credential's `domains`.\n\n" +
        "  On failure the result carries `action`: owner_must_drive (a bot wall or an\n" +
        "  IdP that refuses automation — hand the browser to the owner),\n" +
        "  owner_must_confirm, or fix_credential.\n\n" +
        "  Driving the browser otherwise — opening pages, reading them, clicking — is\n" +
        "  not this CLI's job any more: talk to the same RPC port directly.\n\n" +
        "Unlock: agent-key (auto) | --passphrase-file F | --passphrase-env V |\n" +
        "        owner-approval (approve in the Alien app; --no-owner-approval to skip).\n" +
        "If none works, the command returns VAULT_LOCKED — ask the owner to unlock,\n" +
        "don't retry.",
    ),
});
