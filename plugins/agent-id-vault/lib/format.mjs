// Alien Agent ID — Portable vault format (v2).
//
// Single-file vault with LUKS-style wrapped master key:
//
//   {
//     magic, version, kdf params, cipher params,
//     slots: [ {id, type, ...wrap}, ... ],   // each slot wraps the master key
//     payload: AEAD(master_key, credentials_json),
//   }
//
// Slot types:
//   - passphrase: KEK = scrypt(passphrase, salt, N, r, p);   portability
//   - agent-key:  KEK = HKDF-SHA256(agent_sk, "vault-unlock"); fast unlock
//
// The proposal targets Argon2id; this v1 substitutes Node's built-in scrypt
// to remain zero-dep. The KDF is named in the header, so a future Argon2id
// slot can co-exist with existing scrypt slots.

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  hkdfSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

export const VAULT_MAGIC = "agent-id-vault";
export const VAULT_VERSION = 2;

// scrypt parameters: N=32768, r=8, p=1 → ~32 MB memory, ~300ms on a modern
// laptop. maxmem must be set high enough; node defaults to 32 MB which is
// exactly at the boundary, so we set 64 MB to keep headroom for future bumps.
export const DEFAULT_KDF = Object.freeze({
  name: "scrypt",
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
  keyLen: 32,
});

export const DEFAULT_CIPHER = Object.freeze({ name: "aes-256-gcm" });

const MASTER_KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;

// ─── Master key ─────────────────────────────────────────────────────────────────

export function generateMasterKey() {
  return randomBytes(MASTER_KEY_BYTES);
}

// ─── AEAD helpers (payload + slot wraps both use AES-256-GCM) ───────────────────

function aeadEncrypt(key, plaintext, aad = null) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    ct: ct.toString("hex"),
    tag: tag.toString("hex"),
  };
}

function aeadDecrypt(key, entry, aad = null) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(entry.iv, "hex"),
  );
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(entry.ct, "hex")),
    decipher.final(),
  ]);
}

// ─── KEK derivation ─────────────────────────────────────────────────────────────

function scryptKek(passphrase, salt, kdf = DEFAULT_KDF) {
  return scryptSync(
    Buffer.from(passphrase, "utf8"),
    salt,
    kdf.keyLen,
    { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: kdf.maxmem },
  );
}

function agentKeyKek(privateKeyPem) {
  const privKey = createPrivateKey(privateKeyPem);
  const rawKey = privKey.export({ type: "pkcs8", format: "der" });
  return Buffer.from(
    hkdfSync("sha256", rawKey, "agent-id-vault-v2", "vault-unlock", 32),
  );
}

// ─── Slot construction ──────────────────────────────────────────────────────────

export function buildPassphraseSlot(id, masterKey, passphrase, kdf = DEFAULT_KDF) {
  const salt = randomBytes(SALT_BYTES);
  const kek = scryptKek(passphrase, salt, kdf);
  const wrap = aeadEncrypt(kek, masterKey);
  return {
    id,
    type: "passphrase",
    salt: salt.toString("hex"),
    kdf: { name: kdf.name, N: kdf.N, r: kdf.r, p: kdf.p, keyLen: kdf.keyLen },
    wrap,
  };
}

export function buildAgentKeySlot(id, masterKey, privateKeyPem, agentId = null) {
  const kek = agentKeyKek(privateKeyPem);
  const wrap = aeadEncrypt(kek, masterKey);
  return {
    id,
    type: "agent-key",
    agentId,
    wrap,
  };
}

export function unwrapSlotWithPassphrase(slot, passphrase) {
  if (slot.type !== "passphrase") {
    throw new Error(`Slot ${slot.id} is not a passphrase slot`);
  }
  const kdf = slot.kdf || DEFAULT_KDF;
  const kek = scryptKek(passphrase, Buffer.from(slot.salt, "hex"), {
    ...DEFAULT_KDF,
    ...kdf,
    maxmem: DEFAULT_KDF.maxmem,
  });
  return aeadDecrypt(kek, slot.wrap);
}

export function unwrapSlotWithAgentKey(slot, privateKeyPem) {
  if (slot.type !== "agent-key") {
    throw new Error(`Slot ${slot.id} is not an agent-key slot`);
  }
  const kek = agentKeyKek(privateKeyPem);
  return aeadDecrypt(kek, slot.wrap);
}

// ─── Payload (credentials.json) ─────────────────────────────────────────────────

export function encryptPayload(masterKey, plaintextJsonString) {
  return aeadEncrypt(masterKey, Buffer.from(plaintextJsonString, "utf8"));
}

export function decryptPayload(masterKey, payload) {
  return aeadDecrypt(masterKey, payload).toString("utf8");
}

// ─── Vault file shape ───────────────────────────────────────────────────────────

export function newVaultFile({ masterKey, slots, payloadPlaintext = "{}" }) {
  return {
    magic: VAULT_MAGIC,
    version: VAULT_VERSION,
    cipher: { ...DEFAULT_CIPHER },
    slots,
    payload: encryptPayload(masterKey, payloadPlaintext),
  };
}

export function validateVaultHeader(file) {
  if (!file || typeof file !== "object") {
    throw new Error("Vault file is empty or not an object");
  }
  if (file.magic !== VAULT_MAGIC) {
    throw new Error(`Bad magic: ${file.magic}`);
  }
  if (file.version !== VAULT_VERSION) {
    throw new Error(
      `Unsupported vault version ${file.version} (expected ${VAULT_VERSION}). ` +
        `Run \`agent-id-vault migrate\` to upgrade.`,
    );
  }
  if (!Array.isArray(file.slots) || file.slots.length === 0) {
    throw new Error("Vault has no slots — file is corrupt");
  }
}

// ─── Slot lookup helpers ────────────────────────────────────────────────────────

export function nextSlotId(slots) {
  return slots.reduce((m, s) => Math.max(m, s.id), -1) + 1;
}

export function findPassphraseSlot(slots) {
  return slots.find((s) => s.type === "passphrase") || null;
}

export function findAgentKeySlot(slots) {
  return slots.find((s) => s.type === "agent-key") || null;
}

// Constant-time master-key compare (used in tests + unlock validation).
export function masterKeyEquals(a, b) {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
