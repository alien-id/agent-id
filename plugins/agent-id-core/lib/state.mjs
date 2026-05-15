// Alien Agent ID — State directory I/O helpers.
//
// Every plugin that touches the agent's on-disk state goes through this
// module. Single source of truth for: directory layout (statePaths),
// permission policy (0o700 dirs, 0o600 files), JSON / JSONL serialization,
// and ENOENT-as-empty semantics.

import fs from "node:fs/promises";
import path from "node:path";

async function ensureParent(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
}

export async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true, mode: 0o700 });
}

export async function readJsonFile(filePath, fallback = null) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err && typeof err === "object" && err.code === "ENOENT") {
      return fallback;
    }
    throw err;
  }
}

export async function writeJsonFile(filePath, value, mode = 0o600) {
  await ensureParent(filePath);
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  await fs.writeFile(filePath, payload, { encoding: "utf8", mode });
}

export async function appendJsonl(filePath, value) {
  await ensureParent(filePath);
  const line = `${JSON.stringify(value)}\n`;
  await fs.appendFile(filePath, line, { encoding: "utf8" });
}

export async function readJsonl(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (err) {
    if (err && typeof err === "object" && err.code === "ENOENT") {
      return [];
    }
    throw err;
  }
}

export function statePaths(baseDir) {
  return {
    baseDir,
    ownerSession: path.join(baseDir, "owner-session.json"),
    pendingAuth: path.join(baseDir, "pending-auth.json"),
    nonces: path.join(baseDir, "nonces.json"),
    seq: path.join(baseDir, "sequence.json"),
    mainKey: path.join(baseDir, "keys", "main.json"),
    subagentKeysDir: path.join(baseDir, "keys", "subagents"),
    delegationsDir: path.join(baseDir, "delegations"),
    auditJsonl: path.join(baseDir, "audit", "operations.jsonl"),
    vaultDir: path.join(baseDir, "vault"),
  };
}

export async function setPrivateFilePermissions(filePath) {
  try {
    await fs.chmod(filePath, 0o600);
  } catch {
    // Ignore on unsupported filesystems.
  }
}
