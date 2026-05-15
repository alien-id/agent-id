// Alien Agent ID — Vault crypto.
//
// Encrypted credential storage keyed off the agent's Ed25519 private key.
// The key material never leaves the agent: a stable per-agent AES-256
// encryption key is derived via HKDF-SHA256 over the raw private key bytes.
//
// Encryption is AES-256-GCM with a fresh 12-byte IV per write. The
// authentication tag is stored alongside ciphertext; vaultDecrypt verifies
// it before returning plaintext.
//
// Plugin-private: only agent-id-vault needs these primitives. They do not
// live in agent-id-core.

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";

export function deriveVaultKey(privateKeyPem) {
  const privKey = createPrivateKey(privateKeyPem);
  const rawKey = privKey.export({ type: "pkcs8", format: "der" });
  return Buffer.from(
    hkdfSync("sha256", rawKey, "agent-id-vault-v1", "vault-encryption", 32),
  );
}

export function vaultEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    data: encrypted.toString("hex"),
    tag: tag.toString("hex"),
  };
}

export function vaultDecrypt(key, entry) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(entry.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(entry.data, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
