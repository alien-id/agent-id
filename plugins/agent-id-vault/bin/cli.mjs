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
//   rekey add-passphrase        — append a passphrase slot
//   rekey add-agent-key         — append an agent-key slot
//   rekey add-mobile            — append a phone-approved (mobile) unlock slot
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

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";
import {
  readJsonFile,
  statePaths,
} from "../../agent-id-core/lib/state.mjs";

import {
  exportVault,
  importVault,
  initVault,
  loadAgentPrivateKey,
  openVault,
  vaultFileExists,
} from "../lib/vault.mjs";
import { readLegacyVault } from "../lib/legacy.mjs";
import {
  hasTty,
  promptNewPassphrase,
  promptSecret,
  TrustedInputUnavailable,
} from "../lib/trusted-input.mjs";
import { CREDENTIAL_TYPES } from "../lib/store.mjs";

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

async function openWithFlags(flags, { allowPrompt = true } = {}) {
  const stateDir = resolveStateDir(flags);
  const useAgentKey = flags["agent-key"] !== false; // `--no-agent-key` opts out
  const privateKeyPem = useAgentKey
    ? await loadAgentPrivateKey(stateDir)
    : null;

  // First attempt: agent-key only (no passphrase needed → faster, no prompt).
  if (privateKeyPem && !flags["passphrase-file"] && !flags["passphrase-env"] && !flags.passphrase) {
    try {
      return await openVault({ stateDir, privateKeyPem });
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // Fall through to passphrase.
    }
  }

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

  let passphrase = await resolvePassphrase(flags, { allowPrompt: false });
  if (!passphrase) {
    if (!hasTty()) {
      outputError(
        "Passphrase required. Pass --passphrase-file <path>, --passphrase-env <VAR>, " +
          "or run interactively to enter one.",
      );
      return;
    }
    passphrase = promptNewPassphrase({
      prompt: "New vault passphrase: ",
      confirm: "Confirm passphrase: ",
    });
  }

  const useAgentKey = flags["agent-key"] !== false;
  const privateKeyPem = useAgentKey
    ? await loadAgentPrivateKey(stateDir)
    : null;
  const agentId = privateKeyPem
    ? (await readJsonFile(statePaths(stateDir).mainKey, null))?.agentId || null
    : null;

  const result = await initVault({ stateDir, passphrase, privateKeyPem, agentId });
  stderr(`Vault initialized: ${result.path}`);
  outputJson({ ok: true, ...result });
}

async function cmdAdd(flags) {
  const name = flags.name;
  const type = flags.type;
  if (!name) return outputError("--name <NAME> is required");
  if (!type) return outputError(`--type <${CREDENTIAL_TYPES.join("|")}> is required`);
  if (!CREDENTIAL_TYPES.includes(type)) {
    return outputError(`Unknown type: ${type}. Allowed: ${CREDENTIAL_TYPES.join(", ")}`);
  }
  const domains = parseDomains(flags);
  if (domains.length === 0) {
    return outputError("--domains <host[,host…]> is required (default-deny)");
  }

  const vault = await openWithFlags(flags);
  try {
    const record = { name, type, domains, description: flags.description || null };
    if (flags["upstream-scheme"] != null) {
      record.upstreamScheme = String(flags["upstream-scheme"]);
    }

    switch (type) {
      case "bearer": {
        const value = await resolveValue(flags, "value");
        if (!value) return outputError("Value required (--value-file / --value-env / stdin)");
        record.value = value;
        break;
      }
      case "basic": {
        record.username = flags.username;
        record.password = await resolveValue(flags, "password");
        if (!record.username || !record.password) {
          return outputError("--username and password input required for basic auth");
        }
        break;
      }
      case "header": {
        record.headerName = flags["header-name"];
        record.value = await resolveValue(flags, "value");
        if (!record.headerName || !record.value) {
          return outputError("--header-name and value input required");
        }
        break;
      }
      case "query": {
        record.paramName = flags["param-name"];
        record.value = await resolveValue(flags, "value");
        if (!record.paramName || !record.value) {
          return outputError("--param-name and value input required");
        }
        break;
      }
      case "cookie": {
        record.cookieName = flags["cookie-name"];
        record.value = await resolveValue(flags, "value");
        if (!record.cookieName || !record.value) {
          return outputError("--cookie-name and value input required");
        }
        break;
      }
      case "totp": {
        record.secret = await resolveValue(flags, "secret");
        record.period = Number(flags.period || 30);
        record.digits = Number(flags.digits || 6);
        record.algorithm = flags.algorithm || "SHA1";
        if (!record.secret) return outputError("TOTP secret required");
        break;
      }
      case "cookie-jar": {
        const json = await resolveValue(flags, "jar");
        if (!json) return outputError("Cookie jar JSON required");
        record.cookies = JSON.parse(json);
        break;
      }
      case "oauth2": {
        record.tokenEndpoint = flags["token-endpoint"];
        record.clientId = flags["client-id"];
        const clientSecret = await resolveFileEnvFlag(flags, "client-secret");
        if (clientSecret) record.clientSecret = clientSecret;
        if (flags.scope) record.scope = String(flags.scope);
        // The refresh token is the long-lived secret — read it from file/env/
        // stdin (resolveValue), never argv.
        record.refreshToken = await resolveValue(flags, "refresh-token");
        if (!record.tokenEndpoint || !record.clientId || !record.refreshToken) {
          return outputError(
            "oauth2 needs --token-endpoint, --client-id, and a refresh token " +
              "(--refresh-token-file / --refresh-token-env / stdin)",
          );
        }
        break;
      }
    }

    const stored = vault.add(record);
    await vault.save();
    stderr(`Added credential '${name}' (${type}) for ${domains.join(", ")}.`);
    outputJson({
      ok: true,
      name: stored.name,
      type: stored.type,
      domains: stored.domains,
      createdAt: stored.createdAt,
      updatedAt: stored.updatedAt,
    });
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
    outputJson({ ok: true, credential: rec });
  } finally {
    vault.lock();
  }
}

async function cmdList(flags) {
  const vault = await openWithFlags(flags);
  try {
    outputJson({ ok: true, credentials: vault.list(), slots: vault.slots });
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
        `rekey subcommand required: add-passphrase | add-agent-key | add-mobile | remove-slot`,
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

// ─── Dispatch ───────────────────────────────────────────────────────────────────

function printHelp() {
  stderr(
    [
      "agent-id-vault — portable encrypted credential vault",
      "",
      "Subcommands:",
      "  init [--passphrase-file F | --passphrase-env V] [--no-agent-key]",
      "  add --name N --type T --domains H[,H…] [type-specific value flags]",
      "      oauth2: --token-endpoint URL --client-id ID [--client-secret-env V]",
      "              --refresh-token-file F [--scope S]   (auto-refreshes access tokens)",
      "  show --name N",
      "  list",
      "  remove --name N",
      "  rekey add-passphrase | add-agent-key | remove-slot --id N",
      "        | add-mobile --device-pubkey HEX [--device-id NAME]",
      "  export --out PATH",
      "  import --in PATH [--overwrite]",
      "  migrate [--default-domains H[,H…]] [--force]",
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
  show: cmdShow,
  list: cmdList,
  remove: cmdRemove,
  rekey: makeRekeyHandler(),
  export: cmdExport,
  import: cmdImport,
  migrate: cmdMigrate,
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
