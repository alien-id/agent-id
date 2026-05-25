// Alien Agent ID — Legacy (v4.0.0) vault primitives.
//
// Kept for the one-shot `migrate` path that reads existing per-credential
// files at ~/.agent-id/vault/*.json and re-encrypts them into the new
// portable format. New code MUST NOT use these primitives.

import fs from "node:fs/promises";
import path from "node:path";

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  hkdfSync,
} from "node:crypto";

export function deriveLegacyVaultKey(privateKeyPem) {
  const privKey = createPrivateKey(privateKeyPem);
  const rawKey = privKey.export({ type: "pkcs8", format: "der" });
  return Buffer.from(
    hkdfSync("sha256", rawKey, "agent-id-vault-v1", "vault-encryption", 32),
  );
}

export function legacyDecrypt(key, entry) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(entry.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(entry.data, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

// Kept as a no-op export only so an old import path doesn't silently break
// during the v4→v5 cutover. Anything calling it should be migrated.
export function legacyEncrypt() {
  throw new Error(
    "vaultEncrypt() removed in v5. Use lib/format.mjs + lib/store.mjs instead.",
  );
}

/**
 * Read all legacy per-credential files into a list of {service, type, url,
 * username, credential, createdAt, updatedAt} objects. Caller maps these
 * into the new schema.
 */
export async function readLegacyVault(vaultDir, privateKeyPem) {
  let files;
  try {
    files = await fs.readdir(vaultDir);
  } catch (err) {
    if (err?.code === "ENOENT") return [];
    throw err;
  }
  const key = deriveLegacyVaultKey(privateKeyPem);
  const out = [];
  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const raw = await fs.readFile(path.join(vaultDir, file), "utf8");
    const rec = JSON.parse(raw);
    if (!rec?.encrypted) continue;
    const plaintext = legacyDecrypt(key, rec.encrypted);
    out.push({
      service: rec.service,
      type: rec.type || "api-key",
      url: rec.url || null,
      username: rec.username || null,
      credential: plaintext,
      createdAt: rec.createdAt || null,
      updatedAt: rec.updatedAt || null,
    });
  }
  return out;
}
