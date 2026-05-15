#!/usr/bin/env node

// Alien Agent ID — Vault plugin CLI.
//
// Encrypted credential storage keyed off the agent's identity. Read by
// downstream tools that need an external-service secret (GitHub PAT,
// Slack token, AWS key, …) without hardcoding it. The encryption key is
// derived from the agent's main private key via HKDF-SHA256, so a
// credential is only readable on the same machine as the bound agent.
//
// Subcommands: store, get, list, remove.

import fs from "node:fs/promises";
import path from "node:path";

import {
  ensureDir,
  readJsonFile,
  setPrivateFilePermissions,
  statePaths,
  writeJsonFile,
} from "../../agent-id-core/lib/state.mjs";
import { nowMs } from "../../agent-id-core/lib/crypto.mjs";

import { deriveVaultKey, vaultEncrypt, vaultDecrypt } from "../lib/vault.mjs";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";

// ─── Vault helpers ──────────────────────────────────────────────────────────────

function safeServiceName(name) {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_");
}

async function loadVaultKey(stateDir) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key?.privateKeyPem) {
    throw new Error("No agent keypair. Run `agent-id-setup bootstrap` first.");
  }
  return { vaultKey: deriveVaultKey(key.privateKeyPem), paths };
}

async function readStdin() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
}

async function resolveCredential(flags) {
  // 1. --credential-file <path>  (most secure — never touches CLI args)
  if (flags["credential-file"]) {
    try {
      return (await fs.readFile(flags["credential-file"], "utf8")).replace(/\n$/, "");
    } catch (err) {
      throw new Error(`Cannot read credential file: ${err.message}`);
    }
  }

  // 2. --credential-env <VAR_NAME>  (reads from environment variable)
  if (flags["credential-env"]) {
    const val = process.env[flags["credential-env"]];
    if (!val) throw new Error(`Environment variable ${flags["credential-env"]} is not set`);
    return val;
  }

  // 3. stdin  (piped: echo "secret" | node cli.mjs store ...)
  const fromStdin = await readStdin();
  if (fromStdin) return fromStdin;

  // 4. --credential <value>  (fallback — visible in process list)
  if (flags.credential) return flags.credential;

  return null;
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdStore(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;
  const credType = flags.type || "api-key";

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const credential = await resolveCredential(flags);
  if (!credential) {
    outputError(
      "Credential required. Provide via:\n" +
      "  --credential-file <path>   (read from file — most secure)\n" +
      "  --credential-env <VAR>     (read from environment variable)\n" +
      "  echo 'secret' | <cli> store ...   (pipe via stdin)\n" +
      "  --credential <value>       (CLI arg — visible in process list)",
    );
    return;
  }

  const { vaultKey, paths } = await loadVaultKey(stateDir);
  await ensureDir(paths.vaultDir);

  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);

  // Preserve creation time if updating an existing credential
  const existing = await readJsonFile(filePath, null);
  const encrypted = vaultEncrypt(vaultKey, credential);
  const record = {
    version: 1,
    service,
    type: credType,
    url: flags.url || existing?.url || null,
    username: flags.username || existing?.username || null,
    encrypted,
    createdAt: existing?.createdAt || nowMs(),
    updatedAt: nowMs(),
  };

  await writeJsonFile(filePath, record);
  await setPrivateFilePermissions(filePath);

  stderr(`Stored credential for "${service}" (${credType}).`);
  outputJson({ ok: true, service, type: credType, updated: !!existing });
}

async function cmdGet(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const { vaultKey, paths } = await loadVaultKey(stateDir);
  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);
  const record = await readJsonFile(filePath, null);

  if (!record) {
    outputError(`No credential stored for "${service}".`);
    return;
  }

  const credential = vaultDecrypt(vaultKey, record.encrypted);

  outputJson({
    ok: true,
    service: record.service,
    type: record.type,
    credential,
    url: record.url,
    username: record.username,
  });
}

async function cmdList(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  let files;
  try {
    files = await fs.readdir(paths.vaultDir);
  } catch {
    outputJson({ ok: true, credentials: [] });
    return;
  }

  const credentials = [];
  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const record = await readJsonFile(path.join(paths.vaultDir, file), null);
    if (record?.service) {
      credentials.push({
        service: record.service,
        type: record.type,
        url: record.url,
        username: record.username,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    }
  }

  outputJson({ ok: true, credentials });
}

async function cmdRemove(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const paths = statePaths(stateDir);
  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);

  try {
    await fs.unlink(filePath);
    stderr(`Removed credential for "${service}".`);
    outputJson({ ok: true, service });
  } catch (err) {
    if (err?.code === "ENOENT") {
      outputError(`No credential stored for "${service}".`);
    } else {
      throw err;
    }
  }
}

function printHelp() {
  stderr(
    [
      "agent-id-vault — encrypted credential storage",
      "",
      "Subcommands:",
      "  store --service <NAME> [--type T] [--credential-file F | --credential-env V | --credential S | -]",
      "  get --service <NAME>",
      "  list",
      "  remove --service <NAME>",
      "",
      "Common flags: --state-dir <path> (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
    ].join("\n"),
  );
}

const commands = {
  store: cmdStore,
  get: cmdGet,
  list: cmdList,
  remove: cmdRemove,
};

runCli({ commands, printHelp });
