#!/usr/bin/env node

// Alien Agent ID — Vault plugin CLI.
//
// Portable encrypted credential vault. Backed by a single file
// (~/.agent-id/vault.enc) with a LUKS-style slot construction:
//
//   slot 0: passphrase-wrapped master key (Argon2id-class KDF; scrypt v1)
//   slot 1: agent-key-wrapped master key (fast, unattended unlock)
//
// Subcommands:
//   init                        — create new vault (passphrase + agent-key slots)
//   add                         — add a credential record (typed, domain-scoped)
//   show --name <N>             — retrieve plaintext (use sparingly; prefer the proxy)
//   list                        — metadata only, never plaintext
//   remove --name <N>           — delete a record
//   exec --env VAR=cred.field … -- <cmd>  — run <cmd> with credentials injected
//                                 into its environment (secret never hits disk/argv/stdout)
//   rekey add-passphrase        — append a passphrase slot
//   rekey add-agent-key         — append an agent-key slot
//   rekey add-mobile            — append a phone-approved (mobile) unlock slot
//   rekey add-owner-approval    — append an SSO owner-approval unlock slot
//   rekey remove-slot --id <N>  — remove a slot
//   export --out <PATH>         — copy the encrypted vault file
//   import --in <PATH>          — install an encrypted vault file
//   migrate                     — convert legacy ~/.agent-id/vault/*.json → vault.enc
//
// Unlock inputs:
//   --passphrase-file <path>    — read from file (recommended for automation)
//   --passphrase-env <VAR>      — read from env
//   --unlock-via-agent-key      — explicit; otherwise auto-tried if available
//   (interactive trusted /dev/tty prompt as last resort)

import fs from "node:fs/promises";
import { mkdtempSync, writeFileSync, chmodSync, unlinkSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import {
  outputError,
  outputJson,
  parseFlags,
  resolveStateDir,
  runCli,
  stderr,
} from "@alien-id/agent-id-core/lib/cli-runtime.mjs";
import {
  readJsonFile,
  statePaths,
} from "@alien-id/agent-id-core/lib/state.mjs";

import {
  exportVault,
  importVault,
  initVault,
  loadAgentPrivateKey,
  openVault,
  readPasskeyChallenges,
  vaultFileExists,
} from "../lib/vault.mjs";
import { registerPasskey, authenticatePasskey } from "../lib/passkey.mjs";
import { readLegacyVault } from "../lib/legacy.mjs";
import { ownerApprovalKekBytes } from "../lib/format.mjs";
import { enrollOwnerApproval } from "../lib/owner-approval.mjs";
import { SignatureEngine } from "@alien-id/agent-id-core/lib/signature-engine.mjs";
import {
  hasTty,
  promptNewPassphrase,
  promptSecret,
  promptText,
  TrustedInputUnavailable,
} from "../lib/trusted-input.mjs";
import { CREDENTIAL_TYPES, SECRET_FIELDS, validateRecord } from "../lib/store.mjs";
import {
  ACCESS_LEVELS,
  effectiveAccess,
  isAccessRelaxation,
  isAccessRestricted,
} from "../lib/access.mjs";
import { collectSecret } from "@alien-id/agent-id-core/lib/secure-prompt.mjs";
import { normalizeTotpInput } from "@alien-id/agent-id-core/lib/totp.mjs";
import { generateSolanaKeypair } from "@alien-id/agent-id-core/lib/solana.mjs";
import { generateEvmKeypair } from "@alien-id/agent-id-core/lib/evm.mjs";

import { verifyIdTokenSignatureOnly } from "@alien-id/agent-id-core/lib/oidc.mjs";
import { connectToPeer, startSyncServer } from "../lib/sync/channel.mjs";
import { announceBeacon, listenForBeacons } from "../lib/sync/discovery.mjs";
import { withVaultLock } from "../lib/sync/lock.mjs";
import { runSyncSession } from "../lib/sync/protocol.mjs";
import { ensureSyncMeta, loadSyncIdentity, pinDevice, revokeDevice } from "../lib/sync/trust.mjs";
import { redactSecretFields, parseListenPort } from "../lib/sync/cli-helpers.mjs";

// ─── Input helpers ──────────────────────────────────────────────────────────────

async function readStdin() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const s = Buffer.concat(chunks).toString("utf8");
  return s.length === 0 ? null : s.replace(/\n$/, "");
}

async function resolvePassphrase(flags, { allowPrompt = true, promptMsg = "Passphrase: " } = {}) {
  if (flags["passphrase-file"]) {
    const raw = await fs.readFile(flags["passphrase-file"], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags["passphrase-env"]) {
    const val = process.env[flags["passphrase-env"]];
    if (!val) throw new Error(`Env var ${flags["passphrase-env"]} is not set`);
    return val;
  }
  if (flags.passphrase) return String(flags.passphrase);
  if (allowPrompt && hasTty()) return promptSecret(promptMsg);
  return null;
}

async function resolveValue(flags, fieldName = "credential") {
  if (flags[`${fieldName}-file`]) {
    const raw = await fs.readFile(flags[`${fieldName}-file`], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags[`${fieldName}-env`]) {
    const val = process.env[flags[`${fieldName}-env`]];
    if (!val) throw new Error(`Env var ${flags[`${fieldName}-env`]} is not set`);
    return val;
  }
  const piped = await readStdin();
  if (piped != null) return piped;
  if (hasTty()) return promptSecret(`${fieldName}: `);
  return null;
}

// Read a value from --<field>-file / --<field>-env / --<field> (direct), in
// that order. Unlike resolveValue it never falls back to stdin/tty, so several
// of these can be read in one command (e.g. oauth2's secret + refresh token).
async function resolveFileEnvFlag(flags, field) {
  if (flags[`${field}-file`]) {
    const raw = await fs.readFile(flags[`${field}-file`], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags[`${field}-env`]) {
    const val = process.env[flags[`${field}-env`]];
    if (!val) throw new Error(`Env var ${flags[`${field}-env`]} is not set`);
    return val;
  }
  if (flags[field] != null) return String(flags[field]);
  return null;
}

function parseDomains(flags) {
  const raw = flags.domains;
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Parse a comma-separated flag into a trimmed string array, or null when absent
// (so callers can distinguish "unset" from "empty").
function parseCsvFlag(raw) {
  if (raw == null) return null;
  const list = (Array.isArray(raw) ? raw : String(raw).split(","))
    .map((s) => String(s).trim())
    .filter(Boolean);
  return list.length ? list : null;
}

async function openWithFlags(flags, { allowPrompt = true } = {}) {
  const stateDir = resolveStateDir(flags);
  const useAgentKey = flags["agent-key"] !== false; // `--no-agent-key` opts out
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;
  const hasPassphraseFlag =
    flags["passphrase-file"] || flags["passphrase-env"] || flags.passphrase;

  // 1. Agent-key (fast, unattended) — unless a passphrase was explicitly supplied.
  if (privateKeyPem && !hasPassphraseFlag) {
    try {
      return await openVault({ stateDir, privateKeyPem });
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // fall through
    }
  }

  // 2. An explicit passphrase source (file/env/arg).
  if (hasPassphraseFlag) {
    const passphrase = await resolvePassphrase(flags, { allowPrompt: false });
    return openVault({ stateDir, privateKeyPem, passphrase });
  }

  // 3. A passkey slot → run the WebAuthn ceremony in the browser (preferred over a
  //    /dev/tty prompt; a passkey vault has no passphrase to type).
  if (allowPrompt) {
    const challenges = await readPasskeyChallenges(stateDir);
    if (challenges.length) {
      const prfSecret = await authenticatePasskey(challenges[0]);
      return openVault({ stateDir, passkeyPrfSecret: prfSecret });
    }
  }

  // 4. Interactive passphrase prompt (a dev vault, on a TTY).
  const passphrase = await resolvePassphrase(flags, { allowPrompt });
  return openVault({ stateDir, privateKeyPem, passphrase });
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdInit(flags) {
  const stateDir = resolveStateDir(flags);
  if (await vaultFileExists(stateDir)) {
    outputError(`Vault already exists at ${statePaths(stateDir).vaultFile}`);
    return;
  }

  // Choose the unlock method. `--unlock passkey|passphrase|agent-key` is explicit;
  // otherwise the default is agent-key (user mode). The hard-boundary methods
  // (passkey, passphrase — the agent doesn't hold them) default to NO agent-key
  // slot, so the agent can't silently self-unlock.
  const method = flags.unlock ? String(flags.unlock) : null;
  if (method && !["passkey", "passphrase", "agent-key"].includes(method)) {
    return outputError(`--unlock must be passkey | passphrase | agent-key (got '${method}')`);
  }

  let passphrase = await resolvePassphrase(flags, { allowPrompt: false });
  const dev = flags.dev === true || passphrase != null || method === "passphrase";

  // Passkey: enroll via the secure form (Touch ID / Face ID / security key).
  let passkey = null;
  if (method === "passkey") {
    try {
      passkey = await registerPasskey({ deviceLabel: flags["device-label"] || null });
    } catch (err) {
      return outputError(`passkey registration failed: ${err.message}`);
    }
  }

  // Dev/passphrase path with no passphrase given: prompt on an interactive TTY.
  if (dev && passphrase == null && method !== "passkey" && hasTty()) {
    passphrase = promptNewPassphrase({
      prompt: "New vault passphrase (dev mode): ",
      confirm: "Confirm passphrase: ",
    });
  }

  // Agent-key default: on, EXCEPT when passkey/passphrase was the chosen method.
  const agentKeyDefault = !(method === "passkey" || method === "passphrase");
  const useAgentKey =
    flags["agent-key"] === true || (flags["agent-key"] !== false && agentKeyDefault);
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;
  const agentId = privateKeyPem
    ? (await readJsonFile(statePaths(stateDir).mainKey, null))?.agentId || null
    : null;

  try {
    const result = await initVault({ stateDir, passphrase, privateKeyPem, agentId, passkey, dev });
    stderr(`Vault initialized (${result.mode} mode, ${result.slots} slot${result.slots > 1 ? "s" : ""}): ${result.path}`);
    if (passkey) {
      stderr("Unlock with your passkey (the agent can't unlock it itself). Add `rekey add-passkey` for more devices.");
    } else if (result.mode === "user") {
      stderr(
        "User mode: unlock via agent-key or owner-approval (Alien app). A passphrase " +
          "can never be added, and this vault cannot be converted to dev mode.",
      );
    }
    outputJson({ ok: true, ...result });
  } catch (err) {
    outputError(err.message);
  }
}

// Secret fields each type needs from the out-of-band form (--form). Non-secret
// metadata (header/param/cookie name, token endpoint, client id) still comes from
// flags; only the secret VALUE is typed by the human into the browser form.
function formFieldsForType(type, flags) {
  switch (type) {
    case "bearer": return [{ name: "value", label: "Token / bearer value" }];
    case "header": return [{ name: "value", label: `Value for header "${flags["header-name"]}"` }];
    case "query": return [{ name: "value", label: `Value for query param "${flags["param-name"]}"` }];
    case "cookie": return [{ name: "value", label: `Value for cookie "${flags["cookie-name"]}"` }];
    case "basic": return [
      { name: "username", label: "Username", secret: false },
      { name: "password", label: "Password" },
    ];
    case "totp": return [{ name: "secret", label: "TOTP secret (base32)" }];
    case "secret": return [{ name: "value", label: "Secret — SSH/RSA private key, PEM, JSON, or token", multiline: true }];
    case "cookie-jar": return [{ name: "jar", label: "Cookie jar JSON", multiline: true }];
    case "oauth2": return [
      { name: "client-secret", label: "Client secret", required: false },
      { name: "refresh-token", label: "Refresh token" },
    ];
    case "login": return [
      { name: "username", label: "Username / email", secret: false },
      { name: "password", label: "Password" },
      // Only ask for the 2FA seed up front when the policy is `totp`; otherwise
      // it's added later (when available) via `set-totp`.
      ...(flags.otp === "totp"
        ? [{ name: "totpSecret", label: "TOTP secret (base32) or otpauth:// URI" }]
        : []),
    ];
    default: return null;
  }
}

async function cmdAdd(flags) {
  const name = flags.name;
  const type = flags.type;
  if (!name) return outputError("--name <NAME> is required");
  if (!type) return outputError(`--type <${CREDENTIAL_TYPES.join("|")}> is required`);
  if (!CREDENTIAL_TYPES.includes(type)) {
    return outputError(`Unknown type: ${type}. Allowed: ${CREDENTIAL_TYPES.join(", ")}`);
  }
  const access = flags.access != null ? String(flags.access) : null;
  if (access && !ACCESS_LEVELS.includes(access)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }
  let domains = parseDomains(flags);
  if (domains.length === 0) {
    // `secret` is not host-scoped (it's used via exec/file, not the HTTP proxy),
    // so it doesn't need a domain allowlist; everything else is default-deny.
    if (type === "secret") domains = ["*"];
    else if (type === "login") {
      // `login` is browser-driven, not proxy-injected — domains is advisory. Default
      // to the loginUrl host when given, else "*".
      let host = null;
      if (flags["login-url"]) {
        try {
          host = new URL(String(flags["login-url"])).hostname;
        } catch {
          /* invalid URL caught later by validateRecord */
        }
      }
      domains = host ? [host] : ["*"];
    } else return outputError("--domains <host[,host…]> is required (default-deny)");
  }

  // --form: collect the secret value(s) out of band via a one-shot localhost
  // browser form. The agent supplies the metadata; the human types the value into
  // the form, so it never enters the agent's stdin/stdout/transcript. Validate the
  // required metadata flags FIRST so we don't prompt and then reject.
  let formValues = null;
  if (flags.form) {
    if (type === "header" && !flags["header-name"]) return outputError("--header-name is required");
    if (type === "query" && !flags["param-name"]) return outputError("--param-name is required");
    if (type === "cookie" && !flags["cookie-name"]) return outputError("--cookie-name is required");
    if (type === "oauth2" && (!flags["token-endpoint"] || !flags["client-id"])) {
      return outputError("oauth2 --form needs --token-endpoint and --client-id");
    }
    const specs = formFieldsForType(type, flags);
    if (!specs) {
      return outputError(`--form is not supported for type ${type}`);
    }
    try {
      // collectSecret routes through the secure-prompt resolver (browser form →
      // /dev/tty → hosted harness), so this works where no GUI browser is present.
      const out = await collectSecret({
        title: `Add credential: ${name}`,
        // Show the access level so the human sees the grant they are making
        // while typing the secret ("ro" = the agent can read, never write).
        description: `${type} · ${domains.join(", ")}${access === "ro" ? " · access: READ-ONLY" : ""}`,
        fields: specs,
        label: `enter the "${name}" secret`,
        security:
          "Sealed with <code>AES-256-GCM</code> (key via <code>HKDF-SHA256</code>). Never shown to the agent.",
      });
      formValues = out.values;
    } catch (err) {
      return outputError(`secure form: ${err.message}`);
    }
  }

  // Read a secret either from the form (--form) or the existing file/env/stdin/tty
  // channels — never from argv.
  const secret = (field) =>
    formValues ? Promise.resolve(formValues[field] ?? "") : resolveValue(flags, field);
  const secretFileEnv = (field) =>
    formValues ? Promise.resolve(formValues[field] ?? "") : resolveFileEnvFlag(flags, field);

  const vault = await openWithFlags(flags);
  try {
    const record = { name, type, domains, description: flags.description || null };
    if (flags["upstream-scheme"] != null) {
      record.upstreamScheme = String(flags["upstream-scheme"]);
    }
    if (access) record.access = access;

    // Upserting must never silently widen access: preserve the stored policy
    // when no --access flag is given, and refuse a widening flag — only
    // `set-access` (owner-confirmed) may relax.
    const existing = vault.get(name);
    if (existing) {
      if (!access && existing.access != null) record.access = existing.access;
      if (existing.accessRules != null) record.accessRules = existing.accessRules;
      if (isAccessRelaxation(existing, record)) {
        return outputError(
          `Credential '${name}' has access level '${effectiveAccess(existing)}' — re-adding it ` +
            `with '${access}' would widen what the agent may do. Use \`set-access\` (owner-confirmed).`,
        );
      }
    }

    switch (type) {
      case "bearer":
      case "secret": {
        const value = await secret("value");
        if (!value) return outputError("Value required (--value-file / --value-env / stdin / --form)");
        record.value = value;
        break;
      }
      case "basic": {
        record.username = formValues ? formValues.username : flags.username;
        record.password = await secret("password");
        if (!record.username || !record.password) {
          return outputError("--username and password input required for basic auth");
        }
        break;
      }
      case "header": {
        record.headerName = flags["header-name"];
        record.value = await secret("value");
        if (!record.headerName || !record.value) {
          return outputError("--header-name and value input required");
        }
        break;
      }
      case "query": {
        record.paramName = flags["param-name"];
        record.value = await secret("value");
        if (!record.paramName || !record.value) {
          return outputError("--param-name and value input required");
        }
        break;
      }
      case "cookie": {
        record.cookieName = flags["cookie-name"];
        record.value = await secret("value");
        if (!record.cookieName || !record.value) {
          return outputError("--cookie-name and value input required");
        }
        break;
      }
      case "totp": {
        record.secret = await secret("secret");
        record.period = Number(flags.period || 30);
        record.digits = Number(flags.digits || 6);
        record.algorithm = flags.algorithm || "SHA1";
        if (!record.secret) return outputError("TOTP secret required");
        break;
      }
      case "cookie-jar": {
        const json = await secret("jar");
        if (!json) return outputError("Cookie jar JSON required");
        record.cookies = JSON.parse(json);
        break;
      }
      case "solana-keypair":
      case "evm-keypair": {
        return outputError(
          `${type} credentials are created with \`agent-id-vault generate\` — ` +
            "the private key is generated inside the vault and never crosses a process boundary",
        );
      }
      case "oauth2": {
        record.tokenEndpoint = flags["token-endpoint"];
        record.clientId = flags["client-id"];
        const clientSecret = await secretFileEnv("client-secret");
        if (clientSecret) record.clientSecret = clientSecret;
        if (flags.scope) record.scope = String(flags.scope);
        // The refresh token is the long-lived secret — from form/file/env/stdin, never argv.
        record.refreshToken = await secret("refresh-token");
        if (!record.tokenEndpoint || !record.clientId || !record.refreshToken) {
          return outputError(
            "oauth2 needs --token-endpoint, --client-id, and a refresh token " +
              "(--refresh-token-file / --refresh-token-env / stdin / --form)",
          );
        }
        break;
      }
      case "login": {
        record.username = formValues ? formValues.username : flags.username;
        record.password = await secret("password");
        if (!record.username || !record.password) {
          return outputError("--username and password input required for login");
        }
        const otp = flags.otp ? String(flags.otp) : "none";
        record.otp = otp;
        if (otp === "totp") {
          // Seed from the form, or --totp-secret-file/-env. Accepts a raw base32
          // secret or a full otpauth:// URI; parsed + validated in-vault.
          const seedInput = formValues
            ? formValues.totpSecret
            : await secretFileEnv("totp-secret");
          if (!seedInput) {
            return outputError(
              "otp totp needs a TOTP seed (--form, --totp-secret-file/-env) — " +
                "or add it later with `set-totp`",
            );
          }
          let parsed;
          try {
            parsed = normalizeTotpInput(seedInput);
          } catch (err) {
            return outputError(`TOTP seed: ${err.message}`);
          }
          record.totpSecret = parsed.secret;
          if (parsed.period) record.period = parsed.period;
          if (parsed.digits) record.digits = parsed.digits;
          if (parsed.algorithm) record.algorithm = parsed.algorithm;
        }
        if (flags["login-url"]) record.loginUrl = String(flags["login-url"]);
        if (flags.profile) {
          // The sealed browser-profile is a separate record sharing this name
          // namespace — it must not collide with the login credential's own name.
          if (String(flags.profile) === name) {
            return outputError(
              `--profile '${flags.profile}' must differ from the login name '${name}' ` +
                "(the login and its sealed browser-profile are separate vault records)",
            );
          }
          record.profile = String(flags.profile);
        }
        break;
      }
    }

    const stored = vault.add(record);
    await vault.save();
    stderr(
      `Added credential '${name}' (${type}) for ${domains.join(", ")}` +
        `${stored.access ? ` — access: ${stored.access}` : ""}.`,
    );
    outputJson({
      ok: true,
      name: stored.name,
      type: stored.type,
      domains: stored.domains,
      access: effectiveAccess(stored),
      createdAt: stored.createdAt,
      updatedAt: stored.updatedAt,
    });
  } finally {
    vault.lock();
  }
}

// set-totp: securely attach (or update) a 2FA seed on an existing `login` or
// `totp` credential — for the common case where the seed only becomes available
// AFTER the login was first stored (the user enables 2FA later). The seed is
// entered out-of-band via the secure prompt (so it never enters the agent's
// transcript) and may be a raw base32 secret OR a full otpauth:// URI.
async function cmdSetTotp(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");

  let seedInput;
  if (flags.form) {
    try {
      const out = await collectSecret({
        title: `Set TOTP seed: ${name}`,
        description: "Paste the base32 secret, or the full otpauth:// URI from the QR code",
        fields: [{ name: "seed", label: "TOTP secret (base32) or otpauth:// URI" }],
        label: `enter the TOTP seed for "${name}"`,
        security: "Sealed with <code>AES-256-GCM</code>. Never shown to the agent.",
      });
      seedInput = out.values.seed;
    } catch (err) {
      return outputError(`secure form: ${err.message}`);
    }
  } else {
    seedInput = await resolveValue(flags, "seed"); // --seed-file / --seed-env / stdin / tty
  }
  if (!seedInput) {
    return outputError("TOTP seed required (--form, --seed-file, --seed-env, or stdin)");
  }
  let parsed;
  try {
    parsed = normalizeTotpInput(seedInput);
  } catch (err) {
    return outputError(`TOTP seed: ${err.message}`);
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type === "login") {
      rec.otp = "totp";
      rec.totpSecret = parsed.secret;
    } else if (rec.type === "totp") {
      rec.secret = parsed.secret;
    } else {
      return outputError(`set-totp works on 'login' or 'totp' credentials, not '${rec.type}'`);
    }
    if (parsed.period) rec.period = parsed.period;
    if (parsed.digits) rec.digits = parsed.digits;
    if (parsed.algorithm) rec.algorithm = parsed.algorithm;
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set TOTP seed on '${name}' (${rec.type}).`);
    outputJson({ ok: true, name, type: rec.type, ...(rec.type === "login" ? { otp: "totp" } : {}) });
  } finally {
    vault.lock();
  }
}

async function cmdShow(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    // Two sealing reasons: in-vault-generated secrets never export, and an
    // access-restricted ("ro") credential's plaintext must not reach the agent
    // — otherwise the proxy/browser read-only enforcement would be theater.
    const sealedWhy =
      rec.exportable === false
        ? "generated in-vault, not exportable"
        : isAccessRestricted(rec)
          ? `access-restricted (${describeAccess(rec)}) — enforced via the proxy/browser only`
          : null;
    if (sealedWhy) {
      const redacted = { ...rec };
      for (const f of SECRET_FIELDS) {
        if (redacted[f] != null) redacted[f] = `[sealed — ${sealedWhy}]`;
      }
      stderr(
        `Credential '${name}' is sealed (${sealedWhy}). ` +
          "Use the proxy or the sealed browser to exercise it.",
      );
      outputJson({ ok: true, credential: redacted, sealed: true });
      return;
    }
    outputJson({ ok: true, credential: rec });
  } finally {
    vault.lock();
  }
}

// ─── generate: create a keypair INSIDE the vault; only the public key leaves ───

const GENERATE_TYPES = ["solana-keypair", "evm-keypair"];

async function cmdGenerate(flags) {
  const name = flags.name;
  const type = flags.type || "solana-keypair";
  if (!name) return outputError("--name <NAME> is required");
  if (!GENERATE_TYPES.includes(type)) {
    return outputError(`generate supports types: ${GENERATE_TYPES.join(", ")} (got '${type}')`);
  }
  const domains = parseDomains(flags);
  if (domains.length === 0) {
    return outputError(
      "--domains <host[,host…]> is required (RPC hosts the proxy may sign for, default-deny)",
    );
  }

  const access = flags.access != null ? String(flags.access) : null;
  if (access && !ACCESS_LEVELS.includes(access)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }

  const vault = await openWithFlags(flags);
  try {
    if (vault.has(name) && !flags.overwrite) {
      return outputError(`Credential '${name}' already exists (pass --overwrite to replace it)`);
    }
    const record = {
      name,
      type,
      domains,
      description: flags.description || null,
      exportable: false,
    };
    if (access) record.access = access;
    // Overwriting must not silently widen access (same rule as `add`).
    const existing = vault.get(name);
    if (existing) {
      if (!access && existing.access != null) record.access = existing.access;
      if (existing.accessRules != null) record.accessRules = existing.accessRules;
      if (isAccessRelaxation(existing, record)) {
        return outputError(
          `Credential '${name}' has access level '${effectiveAccess(existing)}' — ` +
            "overwriting cannot widen it. Use `set-access` (owner-confirmed).",
        );
      }
    }
    let address;
    if (type === "solana-keypair") {
      const { publicKey, secretSeedHex } = generateSolanaKeypair();
      record.publicKey = publicKey;
      record.secretSeed = secretSeedHex;
      address = publicKey;
      // Optional signing constraint: restrict which programs the key will sign for.
      const programAllowlist = parseCsvFlag(flags["program-allowlist"]);
      if (programAllowlist) record.programAllowlist = programAllowlist;
    } else {
      const { address: evmAddress, privateKeyHex } = generateEvmKeypair();
      record.address = evmAddress;
      record.privateKey = privateKeyHex;
      address = evmAddress;
      // Optional signing constraints: bound chains and recipients.
      const chainIds = parseCsvFlag(flags["chain-id-allowlist"]);
      if (chainIds) record.chainIdAllowlist = chainIds.map((n) => Number(n));
      const toAllowlist = parseCsvFlag(flags["to-allowlist"]);
      if (toAllowlist) record.toAllowlist = toAllowlist;
    }
    const stored = vault.add(record);
    await vault.save();
    stderr(`Generated ${type === "solana-keypair" ? "Solana" : "EVM"} keypair '${name}'.`);
    stderr(`  Address: ${address}`);
    stderr("  The private key is sealed in the vault and will never be shown.");
    outputJson({
      ok: true,
      name: stored.name,
      type: stored.type,
      ...(record.publicKey ? { publicKey: record.publicKey } : {}),
      ...(record.address ? { address: record.address } : {}),
      domains: stored.domains,
      exportable: false,
      createdAt: stored.createdAt,
    });
  } finally {
    vault.lock();
  }
}

// ─── set-access: change a credential's access level / rules ────────────────────
//
// TIGHTENING (rw→ro, adding deny rules, dropping allow rules) applies
// immediately — an agent may always give capabilities up. RELAXING (ro→rw,
// adding allow rules, dropping deny rules) asks the OWNER to confirm
// out-of-band via the secure prompt (they type the credential name), so an
// agent cannot self-upgrade what its credentials permit.

function describeAccess(rec) {
  const rules = Array.isArray(rec.accessRules) ? ` + ${rec.accessRules.length} rule(s)` : "";
  return `${effectiveAccess(rec)}${rules}`;
}

async function cmdSetAccess(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const wantLevel = flags.access != null ? String(flags.access) : null;
  if (wantLevel && !ACCESS_LEVELS.includes(wantLevel)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }
  let wantRules; // undefined = leave untouched; null = clear; array = replace
  if (flags["clear-rules"] === true) {
    wantRules = null;
  } else if (flags.rules != null) {
    try {
      wantRules = JSON.parse(String(flags.rules));
    } catch (err) {
      return outputError(`--rules must be a JSON array: ${err.message}`);
    }
  }
  if (wantLevel == null && wantRules === undefined) {
    return outputError(
      "Nothing to change — pass --access ro|rw and/or --rules '<JSON array>' / --clear-rules",
    );
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);

    const after = { ...rec };
    if (wantLevel != null) after.access = wantLevel;
    if (wantRules !== undefined) {
      if (wantRules == null) delete after.accessRules;
      else after.accessRules = wantRules;
    }
    try {
      validateRecord(after); // fail fast, before any owner ceremony
    } catch (err) {
      return outputError(err.message);
    }

    if (isAccessRelaxation(rec, after)) {
      stderr(
        `Widening access on '${name}' (${describeAccess(rec)} → ${describeAccess(after)}) ` +
          "needs the owner's out-of-band confirmation…",
      );
      let values;
      try {
        ({ values } = await collectSecret({
          title: `Allow MORE access: ${name}`,
          description:
            `The agent asks to widen what '${name}' may do: ` +
            `${describeAccess(rec)} → ${describeAccess(after)}. ` +
            "Approve only if YOU intend this.",
          fields: [
            {
              name: "confirm",
              label: `Type the credential name (${name}) to approve`,
              secret: false,
            },
          ],
          label: `approve wider access for "${name}"`,
          security: "Typed by you, out of the agent's sight. Mismatch = no change.",
        }));
      } catch (err) {
        return outputError(`owner confirmation: ${err.message}`);
      }
      if (String(values.confirm || "").trim() !== name) {
        return outputError("owner confirmation did not match the credential name — access unchanged");
      }
    }

    vault.add(after);
    await vault.save();
    stderr(`Access on '${name}' is now: ${describeAccess(after)}.`);
    outputJson({
      ok: true,
      name,
      access: effectiveAccess(after),
      accessRules: after.accessRules ?? null,
    });
  } finally {
    vault.lock();
  }
}

async function cmdList(flags) {
  const vault = await openWithFlags(flags);
  try {
    outputJson({ ok: true, mode: vault.mode, credentials: vault.list(), slots: vault.slots });
  } finally {
    vault.lock();
  }
}

async function cmdRemove(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const removed = vault.remove(name);
    if (!removed) return outputError(`No credential named '${name}'`);
    await vault.save();
    stderr(`Removed credential '${name}'.`);
    outputJson({ ok: true, name });
  } finally {
    vault.lock();
  }
}

async function cmdRekey(flags) {
  const sub = flags._sub;
  const vault = await openWithFlags(flags);
  try {
    if (sub === "add-passphrase") {
      let passphrase = await resolvePassphrase(
        { ...flags, "passphrase-file": flags["new-passphrase-file"], "passphrase-env": flags["new-passphrase-env"], passphrase: flags["new-passphrase"] },
        { allowPrompt: false },
      );
      if (!passphrase) {
        if (!hasTty()) return outputError("New passphrase required");
        passphrase = promptNewPassphrase({
          prompt: "New passphrase: ",
          confirm: "Confirm: ",
        });
      }
      const slot = vault.addPassphraseSlot(passphrase);
      await vault.save();
      stderr(`Added passphrase slot ${slot.id}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type } });
    } else if (sub === "add-agent-key") {
      const stateDir = resolveStateDir(flags);
      const privateKeyPem = await loadAgentPrivateKey(stateDir);
      if (!privateKeyPem) return outputError("No agent key found. Run agent-id-core bootstrap first.");
      const agentId =
        (await readJsonFile(statePaths(stateDir).mainKey, null))?.agentId || null;
      const slot = vault.addAgentKeySlot(privateKeyPem, agentId);
      await vault.save();
      stderr(`Added agent-key slot ${slot.id} for agent ${agentId || "(unknown)"}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type, agentId } });
    } else if (sub === "add-passkey") {
      let passkey;
      try {
        passkey = await registerPasskey({ deviceLabel: flags["device-label"] || null });
      } catch (err) {
        return outputError(`passkey registration failed: ${err.message}`);
      }
      const slot = vault.addPasskeySlot(passkey.prfSecret, {
        credentialId: passkey.credentialId,
        rpId: passkey.rpId,
        prfSalt: passkey.prfSalt,
        deviceLabel: passkey.deviceLabel,
      });
      await vault.save();
      stderr(`Added passkey slot ${slot.id}${passkey.deviceLabel ? ` (${passkey.deviceLabel})` : ""}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type, credentialId: passkey.credentialId } });
    } else if (sub === "add-mobile") {
      const devicePubKey = flags["device-pubkey"];
      if (!devicePubKey) {
        return outputError(
          "--device-pubkey <hex> required (P-256 enclave public key, X9.63 uncompressed: 04||X||Y)",
        );
      }
      if (!/^04[0-9a-fA-F]{128}$/.test(devicePubKey)) {
        return outputError(
          "--device-pubkey must be 130 hex chars starting with 04 (uncompressed P-256 point)",
        );
      }
      const deviceId = flags["device-id"] || null;
      const slot = vault.addMobileSlot(devicePubKey, deviceId);
      await vault.save();
      stderr(`Added mobile slot ${slot.id}${deviceId ? ` for device ${deviceId}` : ""}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type, deviceId } });
    } else if (sub === "add-owner-approval") {
      const stateDir = resolveStateDir(flags);
      const engine = new SignatureEngine({ baseDir: stateDir });
      const main = await engine.ensureMainKey();
      const session = await engine.ensureValidSession();
      if (!session?.accessToken) {
        return outputError(
          "No valid owner session. Run `agent-id-core auth` to bind an owner first.",
        );
      }
      const ssoBaseUrl = flags["sso-url"] || session.ssoBaseUrl || session.issuer;
      if (!ssoBaseUrl) {
        return outputError("Could not determine SSO base URL — pass --sso-url <URL>.");
      }
      const providerAddress = flags["provider-address"] || session.providerAddress || null;

      // The KEK lives only long enough to wrap the master key and hand a copy to
      // the SSO; it is zeroed below so neither the vault file nor this process
      // retains it. Recovery requires an owner-approved release from the SSO.
      const kek = ownerApprovalKekBytes();
      try {
        const { keyRef } = await enrollOwnerApproval({
          ssoBaseUrl,
          accessToken: session.accessToken,
          agentPrivateKeyPem: main.privateKeyPem,
          secret: kek,
        });
        const slot = vault.addOwnerApprovalSlot(kek, { keyRef, ssoBaseUrl, providerAddress });
        await vault.save();
        stderr(`Added owner-approval slot ${slot.id} (key_ref ${keyRef}).`);
        outputJson({ ok: true, slot: { id: slot.id, type: slot.type, keyRef } });
      } finally {
        kek.fill(0);
      }
    } else if (sub === "remove-slot") {
      const id = Number(flags.id);
      if (!Number.isFinite(id)) return outputError("--id <N> required");
      const ok = vault.removeSlot(id);
      if (!ok) return outputError(`No slot with id ${id}`);
      await vault.save();
      stderr(`Removed slot ${id}.`);
      outputJson({ ok: true, removed: id });
    } else {
      return outputError(
        `rekey subcommand required: add-passphrase | add-passkey | add-agent-key | add-mobile | add-owner-approval | remove-slot`,
      );
    }
  } finally {
    vault.lock();
  }
}

async function cmdExport(flags) {
  const out = flags.out;
  if (!out) return outputError("--out <PATH> is required");
  const stateDir = resolveStateDir(flags);
  if (!(await vaultFileExists(stateDir))) {
    return outputError("No vault to export");
  }
  const written = await exportVault({ stateDir, outPath: out });
  stderr(`Exported encrypted vault to ${written}`);
  outputJson({ ok: true, path: written });
}

async function cmdImport(flags) {
  const inPath = flags.in;
  if (!inPath) return outputError("--in <PATH> is required");
  const stateDir = resolveStateDir(flags);
  const written = await importVault({
    stateDir,
    inPath,
    overwrite: Boolean(flags.overwrite),
  });
  stderr(`Imported encrypted vault to ${written}`);
  outputJson({ ok: true, path: written });
}

async function cmdMigrate(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  if (await vaultFileExists(stateDir)) {
    if (!flags["force"]) {
      return outputError(
        `Portable vault already exists at ${paths.vaultFile}. ` +
          "Pass --force to re-run migration (will not overwrite existing slots).",
      );
    }
  }

  const privateKeyPem = await loadAgentPrivateKey(stateDir);
  if (!privateKeyPem) return outputError("No agent key — cannot decrypt legacy vault.");

  const legacy = await readLegacyVault(paths.vaultDir, privateKeyPem);
  if (legacy.length === 0) {
    stderr("No legacy credentials found — nothing to migrate.");
    outputJson({ ok: true, migrated: 0 });
    return;
  }

  let passphrase = await resolvePassphrase(flags, { allowPrompt: false });
  if (!passphrase) {
    if (!hasTty()) return outputError("Migration requires a passphrase for slot 0");
    passphrase = promptNewPassphrase({
      prompt: "New vault passphrase (for portability): ",
      confirm: "Confirm: ",
    });
  }
  const agentId =
    (await readJsonFile(paths.mainKey, null))?.agentId || null;

  await initVault({ stateDir, passphrase, privateKeyPem, agentId });
  const vault = await openVault({ stateDir, privateKeyPem });
  try {
    for (const old of legacy) {
      // Legacy v4 records had no host allowlist; require migrate caller to
      // supply --default-domains, otherwise we tag them as "unrestricted"
      // so the proxy refuses to use them until the user attaches a domain.
      const domains =
        parseDomains({ domains: flags["default-domains"] }) || [];
      vault.add({
        name: old.service,
        type: "bearer",
        domains: domains.length > 0 ? domains : ["UNCONFIGURED.invalid"],
        description: `migrated from v4 (${old.type})`,
        value: old.credential,
      });
    }
    await vault.save();
    stderr(`Migrated ${legacy.length} legacy credentials.`);
    if (!flags["default-domains"]) {
      stderr(
        "WARNING: legacy records have no host allowlist. " +
          "Update each with `agent-id-vault add --name <N> --type bearer --domains <H> --value-env <V>` " +
          "before the proxy will inject them.",
      );
    }
    // Rename old dir so a re-run notices it's done.
    try {
      await fs.rename(paths.vaultDir, `${paths.vaultDir}.bak`);
    } catch {
      // not fatal
    }
    outputJson({ ok: true, migrated: legacy.length, vault: paths.vaultFile });
  } finally {
    vault.lock();
  }
}

// ─── exec: run a command with vault credentials injected into its env / a file ──
//
// Two materialization modes, both keeping the secret out of the agent's
// stdin/stdout/argv/transcript (only the variable names + sources are logged):
//
//   --env  VAR=cred.field   inject the value into the child's environment.
//   --file VAR=cred.field   write the value to a temp 0600 file and set VAR to its
//                           PATH — for tools that want a key FILE (ssh -i, an RSA
//                           PEM, a service-account JSON). The agent gets the path,
//                           never the contents; the file is shredded + removed when
//                           the command exits.
//
//   agent-id-vault exec [--env … | --file …] [unlock flags] -- <cmd> [args…]
//
// Examples:
//   exec --env MODAL_TOKEN_ID=modal-token.username --env MODAL_TOKEN_SECRET=modal-token.password -- modal run job.py
//   exec --file GIT_SSH_KEY=deploy-key.value -- sh -c 'GIT_SSH_COMMAND="ssh -i $GIT_SSH_KEY" git fetch'
//
// `field` is the record field to read (bearer/header/query/cookie → value, basic →
// username/password, totp → secret, oauth2 → refreshToken, secret → value, …).
// Sealed in-vault-generated keys (solana/evm) refuse to leave the vault.
async function cmdExec() {
  const rest = process.argv.slice(3); // drop ["exec"]; argv[2] === "exec"
  const sepIdx = rest.indexOf("--");
  if (sepIdx === -1) {
    return outputError(
      "exec needs a `--` separator before the command. " +
        "Usage: exec --env VAR=cred.field | --file VAR=cred.field [more] -- <command> [args…]",
    );
  }
  const pre = rest.slice(0, sepIdx);
  const cmdArgv = rest.slice(sepIdx + 1);
  if (cmdArgv.length === 0) return outputError("No command given after `--`.");

  // --env / --file are repeatable (parseFlags would keep only the last); collect
  // them by hand and leave the rest as unlock/common flags.
  const mappings = [];
  const flagArgs = [];
  for (let i = 0; i < pre.length; i++) {
    if (pre[i] === "--env" || pre[i] === "--file") {
      const v = pre[i + 1];
      if (!v || v.startsWith("--")) {
        return outputError(`${pre[i]} needs a VAR=cred.field argument`);
      }
      mappings.push({ kind: pre[i] === "--file" ? "file" : "env", ref: v });
      i++;
    } else {
      flagArgs.push(pre[i]);
    }
  }
  if (mappings.length === 0) {
    return outputError("exec needs at least one --env or --file VAR=cred.field mapping");
  }

  const specs = [];
  for (const m of mappings) {
    const eq = m.ref.indexOf("=");
    if (eq <= 0) return outputError(`Bad --${m.kind} "${m.ref}" — expected VAR=cred.field`);
    const varName = m.ref.slice(0, eq);
    const ref = m.ref.slice(eq + 1);
    const dot = ref.lastIndexOf(".");
    if (dot <= 0 || dot === ref.length - 1) {
      return outputError(
        `Bad --${m.kind} "${m.ref}" — expected VAR=cred.field (e.g. GIT_SSH_KEY=deploy-key.value)`,
      );
    }
    specs.push({ kind: m.kind, varName, credName: ref.slice(0, dot), field: ref.slice(dot + 1) });
  }

  const flags = parseFlags(flagArgs);
  const vault = await openWithFlags(flags);
  const childEnv = { ...process.env };
  const injected = [];
  let tmpDir = null;
  const files = [];
  try {
    for (const s of specs) {
      const rec = vault.get(s.credName);
      if (!rec) return outputError(`No credential named '${s.credName}'`);
      if (rec.exportable === false && SECRET_FIELDS.includes(s.field)) {
        return outputError(
          `Credential '${s.credName}' is sealed (generated in-vault); field ` +
            `'${s.field}' cannot leave the vault. Use the proxy to exercise it.`,
        );
      }
      // An access-restricted credential (ro, OR rw with deny rules) handed raw
      // to a child process would bypass the proxy/browser gate — refuse, same
      // as sealed. Rule-only restrictions count: the rules are enforced at the
      // proxy, so leaking the plaintext would make them theater.
      if (isAccessRestricted(rec) && SECRET_FIELDS.includes(s.field)) {
        return outputError(
          `Credential '${s.credName}' is access-restricted (${describeAccess(rec)}); field ` +
            `'${s.field}' cannot be exported to a child process (that would bypass enforcement). ` +
            "Use the proxy/browser, or ask the owner to run `set-access --access rw` (and clear rules).",
        );
      }
      const value = rec[s.field];
      if (typeof value !== "string" || value.length === 0) {
        return outputError(`Credential '${s.credName}' has no usable string field '${s.field}'`);
      }
      if (s.kind === "file") {
        // mkdtemp makes a 0700 dir; the file is 0600. Same-uid isn't a boundary
        // (the agent could read the vault anyway) — this keeps the value out of
        // the transcript/argv and bounds its on-disk lifetime to the command.
        if (!tmpDir) tmpDir = mkdtempSync(path.join(os.tmpdir(), "agent-id-exec-"));
        const safe = s.varName.replace(/[^A-Za-z0-9._-]/g, "_") || "secret";
        const fp = path.join(tmpDir, safe);
        writeFileSync(fp, value, { mode: 0o600 });
        chmodSync(fp, 0o600); // enforce 0600 regardless of umask
        childEnv[s.varName] = fp;
        files.push(fp);
        injected.push(`${s.varName}=${s.credName}.${s.field} (file)`);
      } else {
        childEnv[s.varName] = value;
        injected.push(`${s.varName}=${s.credName}.${s.field}`);
      }
    }
  } finally {
    vault.lock(); // values already copied; zero the master key
  }

  // Best-effort shred of any materialized files: overwrite with zeros, unlink,
  // remove the dir. Sync so it completes inside the exit handlers.
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    for (const fp of files) {
      try { writeFileSync(fp, Buffer.alloc(statSync(fp).size, 0)); } catch {}
      try { unlinkSync(fp); } catch {}
    }
    if (tmpDir) {
      try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  };

  // Names + sources only — never the values.
  stderr(`Injecting ${injected.join(", ")} → ${cmdArgv.join(" ")}`);

  const child = spawn(cmdArgv[0], cmdArgv.slice(1), { stdio: "inherit", env: childEnv });
  const forward = (sig) => {
    try {
      child.kill(sig);
    } catch {
      /* child already exited */
    }
  };
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  process.on("exit", cleanup); // last-resort sync cleanup of temp files
  child.on("error", (err) => {
    process.off("SIGINT", forward);
    process.off("SIGTERM", forward);
    cleanup();
    outputError(`Failed to run '${cmdArgv[0]}': ${err.message}`);
  });
  child.on("exit", (code, signal) => {
    process.off("SIGINT", forward);
    process.off("SIGTERM", forward);
    cleanup();
    process.exitCode = signal ? 1 : (code ?? 0);
  });
}

// ─── sync ───────────────────────────────────────────────────────────────────────

function promptApproval(peer) {
  if (process.env.AGENT_ID_SYNC_AUTOAPPROVE === "1") {
    // Escape hatch for automated e2e (Docker) — never silent: surface a loud
    // warning naming the peer so it is auditable in the driving process's logs.
    stderr(
      `⚠ AGENT_ID_SYNC_AUTOAPPROVE: auto-trusting sync peer ${peer.jkt} without human review`,
    );
    return Promise.resolve(true);
  }
  if (!hasTty()) return Promise.resolve(false); // headless → approval-required path
  // Read the y/N answer from the trusted /dev/tty channel — NOT process.stdin —
  // so an agent driving this CLI over its stdin pipe cannot answer its own
  // security prompt.
  const q =
    `\nNew sync peer:\n` +
    `  device : ${peer.label || "(unlabelled)"}\n` +
    `  agent  : ${peer.jkt}\n` +
    `  owner  : verified — same as this device (L${peer.level ?? "?"})\n` +
    `Trust this device and sync credentials with it? [y/N] `;
  let answer;
  try {
    answer = promptText(q);
  } catch (err) {
    if (err instanceof TrustedInputUnavailable) return Promise.resolve(false);
    throw err;
  }
  return Promise.resolve(/^y(es)?$/i.test(answer.trim()));
}

async function syncWith(stateDir, vault, identity, session) {
  return withVaultLock(stateDir, () =>
    runSyncSession({
      session,
      vault,
      identity,
      approvePeer: promptApproval,
      verifyIdToken: verifyIdTokenSignatureOnly,
    }),
  );
}

function describeSummary(summary) {
  return {
    peer: summary.peer,
    sent: summary.sent,
    received: summary.received,
    conflicts: summary.conflicts.map((c) => ({ name: c.name, winnerHash: c.winnerHash })),
  };
}

async function cmdSyncRun(flags) {
  const stateDir = resolveStateDir(flags);
  const identity = await loadSyncIdentity(stateDir, flags.label ? { label: String(flags.label) } : {});

  if (flags.listen) {
    // parseFlags yields boolean `true` for a bare flag, so validate coercions
    // up-front rather than binding a bogus host/port silently.
    let port;
    try {
      port = parseListenPort(flags);
    } catch (err) {
      return outputError(err.message);
    }
    if (flags.host != null && typeof flags.host !== "string") {
      return outputError("--host must be a hostname/address string");
    }
    const host = flags.host ? String(flags.host) : "0.0.0.0";

    const srv = await startSyncServer({
      host,
      port,
      // Each incoming session gets its OWN short-lived vault handle: opened
      // inside the process-level withVaultLock, then locked in a finally. This
      // keeps the master key + plaintext secrets out of memory between sessions
      // and re-reads the pinned-device set from disk each time (so an out-of-band
      // `sync devices add` from another process takes effect without a restart).
      onSession: async (session) => {
        try {
          const summary = await withVaultLock(stateDir, async () => {
            const vault = await openWithFlags(flags);
            try {
              return await runSyncSession({
                session,
                vault,
                identity,
                approvePeer: promptApproval,
                verifyIdToken: verifyIdTokenSignatureOnly,
              });
            } finally {
              vault.lock();
            }
          });
          stderr(`✓ synced with ${summary.peer.label || summary.peer.jkt}: +${summary.received} / -${summary.sent} ops` +
            (summary.conflicts.length ? `, ${summary.conflicts.length} conflict(s) journaled` : ""));
        } catch (err) {
          stderr(`✗ sync refused: ${err.message}`);
        }
      },
    });
    const beacon = announceBeacon({ deviceJkt: identity.jkt, tcpPort: srv.port });
    stderr(`Sync listener on port ${srv.port} (device ${identity.jkt}, label "${identity.label}"). Ctrl-C to stop.`);
    await new Promise((resolve) => {
      process.once("SIGINT", resolve);
      process.once("SIGTERM", resolve);
    });
    beacon.stop();
    await srv.close();
    return;
  }

  // One-shot: explicit --peer wins; otherwise listen for beacons briefly.
  let peers = [];
  if (flags.peer) {
    if (typeof flags.peer !== "string") return outputError("--peer must be host:port");
    const [host, port] = flags.peer.split(":");
    if (!host || !port) return outputError("--peer must be host:port");
    peers = [{ host, port: Number(port) }];
  } else {
    stderr("Discovering peers on the local network…");
    peers = await listenForBeacons({
      timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : 2500,
      ownJkt: identity.jkt,
    });
    if (peers.length === 0) {
      return outputError("no sync peers found — is the other device running `agent-id-vault sync --listen`? (or pass --peer host:port)");
    }
  }

  // Short-lived: open the vault once, sync each peer, lock in a finally.
  const vault = await openWithFlags(flags);
  const results = [];
  try {
    for (const peer of peers) {
      try {
        const session = await connectToPeer({ host: peer.host, port: peer.port });
        const summary = await syncWith(stateDir, vault, identity, session);
        results.push({ ok: true, ...describeSummary(summary) });
      } catch (err) {
        results.push({ ok: false, peer: `${peer.host}:${peer.port}`, error: err.message, code: err.code || null });
      }
    }
  } finally {
    vault.lock();
  }
  outputJson({ ok: results.every((r) => r.ok), results });
}

async function cmdSyncStatus(flags) {
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  outputJson({
    ok: true,
    ops: sync.oplog.length,
    devices: sync.devices.map((d) => ({ jkt: d.deviceJkt, label: d.label, ownerSub: d.ownerSub, addedAt: d.addedAt, complete: Boolean(d.agentJwk) })),
    conflicts: sync.conflicts.map((c) => ({ name: c.name, winnerHash: c.winnerHash, decidedAt: c.decidedAt })),
  });
}

async function cmdSyncDevices(flags) {
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  if (flags._sub2 === "add") {
    if (!flags.jkt) return outputError("sync devices add requires --jkt <thumbprint> (from the other device's approval-required log)");
    pinDevice(sync, { deviceJkt: String(flags.jkt), label: flags.label ? String(flags.label) : null });
    await vault.save();
    stderr(`Preapproved device ${flags.jkt} — its key is pinned on first verified contact.`);
    return outputJson({ ok: true, jkt: String(flags.jkt) });
  }
  outputJson({ ok: true, devices: sync.devices.map((d) => ({ jkt: d.deviceJkt, label: d.label, complete: Boolean(d.agentJwk) })) });
}

async function cmdSyncRevoke(flags) {
  if (!flags.jkt) return outputError("sync revoke requires --jkt <thumbprint>");
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  const removed = revokeDevice(sync, String(flags.jkt));
  if (removed) await vault.save();
  outputJson({ ok: removed, ...(removed ? {} : { error: "device not found" }) });
}

async function cmdSyncResolve(flags) {
  if (!flags.name) return outputError("sync resolve requires --name <credential>");
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  const entries = sync.conflicts.filter((c) => c.name === flags.name);
  if (entries.length === 0) return outputError(`no journaled conflicts for "${flags.name}"`);
  const latest = entries[entries.length - 1];
  if (!flags.restore) {
    return outputJson({
      ok: true, name: latest.name, winnerHash: latest.winnerHash,
      current: vault.get(String(flags.name)) ? "present" : "removed",
      losingRecord: redactSecretFields(latest.losingRecord),
      hint: "re-run with --restore to reinstate the losing version as a new edit",
    });
  }
  // Reinstating = a NEW causally-later edit; it wins everywhere on next sync.
  vault.add({ ...latest.losingRecord });
  sync.conflicts = sync.conflicts.filter((c) => c !== latest);
  await vault.save();
  stderr(`Restored the journaled version of "${flags.name}". It will propagate on the next sync.`);
  outputJson({ ok: true, restored: flags.name });
}

// `sync` takes an optional sub-verb as its first positional arg (like rekey).
function makeSyncHandler() {
  return async (flags) => {
    const argv = process.argv.slice(2);
    const idx = argv.indexOf("sync");
    const sub = idx >= 0 && argv[idx + 1] && !argv[idx + 1].startsWith("--") ? argv[idx + 1] : null;
    const sub2 = sub && argv[idx + 2] && !argv[idx + 2].startsWith("--") ? argv[idx + 2] : null;
    if (sub === "status") return cmdSyncStatus(flags);
    if (sub === "devices") return cmdSyncDevices({ ...flags, _sub2: sub2 });
    if (sub === "revoke") return cmdSyncRevoke(flags);
    if (sub === "resolve") return cmdSyncResolve(flags);
    if (sub) return outputError(`Unknown sync subcommand: ${sub}`);
    return cmdSyncRun(flags);
  };
}

// ─── Dispatch ───────────────────────────────────────────────────────────────────

function printHelp() {
  stderr(
    [
      "agent-id-vault — portable encrypted credential vault",
      "",
      "Subcommands:",
      "  init [--unlock passkey|passphrase|agent-key] [--dev] [--no-agent-key] [--agent-key]",
      "       --unlock passkey     Touch ID / Face ID / security key (recommended; agent can't self-unlock)",
      "       --unlock passphrase  typed into the secure form (dev mode)",
      "       default (no --unlock) = USER mode, agent-key auto-unlock.",
      "       passkey/passphrase default to NO agent-key slot; add --agent-key to keep one.",
      "  add --name N --type T --domains H[,H…] [--access ro|rw] [type-specific value flags]",
      "      --form   enter the secret out-of-band via the secure prompt (browser",
      "               form → /dev/tty → hosted harness); else --<field>-file/-env/stdin",
      "      --access ro   read-only: the proxy/browser allow only read-shaped",
      "               requests (GET/HEAD/OPTIONS + POST-tunneled reads: GraphQL",
      "               query, JMAP get/query, JSON-RPC non-submitting); show/exec",
      "               refuse the plaintext. Default rw (unrestricted).",
      "      oauth2: --token-endpoint URL --client-id ID [--client-secret-env V]",
      "              --refresh-token-file F [--scope S]   (auto-refreshes access tokens)",
      "      login:  --login-url URL [--otp none|totp|interactive] [--profile NAME]",
      "              --form captures username/password (+ TOTP seed when --otp totp);",
      "              driven by `agent-id-browser auto-login`, not the HTTP proxy",
      "  set-totp --name N [--form]   attach/update a 2FA seed on a login|totp cred",
      "              accepts a base32 secret or an otpauth:// URI (use when 2FA is",
      "              enabled after the login was stored); else --seed-file/-env/stdin",
      "  set-access --name N [--access ro|rw] [--rules '<JSON>' | --clear-rules]",
      "              change a credential's access level. Tightening applies at",
      "              once; WIDENING requires the owner to confirm via the secure",
      "              prompt (the agent cannot self-upgrade). Rules: JSON array of",
      '              {"effect":"allow|deny","methods":[..],"hosts":[..],"path":"/glob*"}',
      "  generate --name N --type solana-keypair|evm-keypair --domains H[,H…] [--overwrite]",
      "      creates the keypair inside the vault; prints ONLY the public address",
      "      evm:    [--chain-id-allowlist 1,137] [--to-allowlist 0x..,0x..]",
      "      solana: [--program-allowlist <base58>,..]   (default-allow when omitted)",
      "  show --name N    (sealed/generated secrets are redacted)",
      "  list",
      "  remove --name N",
      "  exec [--env VAR=cred.field | --file VAR=cred.field] … -- <cmd> [args…]",
      "      run <cmd> with credentials injected; the agent never sees the value.",
      "      --env  → into the child's environment (MODAL_TOKEN_ID=modal-token.username)",
      "      --file → written to a temp 0600 file, VAR=its path, shredded on exit",
      "               (for key files: GIT_SSH_KEY=deploy-key.value)",
      "  rekey add-passkey [--device-label NAME]   add a passkey (Touch ID) unlock",
      "        | add-passphrase | add-agent-key | remove-slot --id N",
      "        | add-mobile --device-pubkey HEX [--device-id NAME]",
      "        | add-owner-approval [--sso-url URL] [--provider-address ADDR]",
      "  export --out PATH",
      "  import --in PATH [--overwrite]",
      "  migrate [--default-domains H[,H…]] [--force]",
      "  sync [--peer H:P] [--listen [--port N] [--host H]] [--label L]",
      "  sync status | devices [add --jkt J] | revoke --jkt J | resolve --name N [--restore]",
      "",
      "Types: " + CREDENTIAL_TYPES.join(", "),
      "Unlock: --passphrase-file F | --passphrase-env V | auto via agent-key | /dev/tty prompt",
      "Common: --state-dir <path>  (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
    ].join("\n"),
  );
}

// `rekey` takes a sub-verb as its first positional arg; wrap dispatch.
function makeRekeyHandler() {
  return async (flags) => {
    const argv = process.argv.slice(2);
    const idx = argv.indexOf("rekey");
    const sub = idx >= 0 ? argv[idx + 1] : null;
    await cmdRekey({ ...flags, _sub: sub });
  };
}

const commands = {
  init: cmdInit,
  add: cmdAdd,
  "set-totp": cmdSetTotp,
  "set-access": cmdSetAccess,
  generate: cmdGenerate,
  show: cmdShow,
  list: cmdList,
  remove: cmdRemove,
  exec: cmdExec,
  rekey: makeRekeyHandler(),
  export: cmdExport,
  import: cmdImport,
  migrate: cmdMigrate,
  sync: makeSyncHandler(),
};

// Wrap runCli to catch trusted-input + vault-not-found errors with friendlier
// messages.
const originalCommands = { ...commands };
for (const k of Object.keys(commands)) {
  commands[k] = async (flags) => {
    try {
      await originalCommands[k](flags);
    } catch (err) {
      if (err instanceof TrustedInputUnavailable) {
        outputError(err.message);
      } else if (err.code === "VAULT_NOT_FOUND") {
        outputError(err.message);
      } else if (err.code === "VAULT_UNLOCK_FAILED") {
        outputError(err.message);
      } else if (err.code === "VAULT_EXISTS") {
        outputError(err.message);
      } else {
        throw err;
      }
    }
  };
}

runCli({ commands, printHelp });
