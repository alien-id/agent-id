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
//   - mobile:     KEK = HKDF-SHA256(ECDH(ephemeral, device_pk)); phone-approved
//
// The proposal targets Argon2id; this v1 substitutes Node's built-in scrypt
// to remain zero-dep. The KDF is named in the header, so a future Argon2id
// slot can co-exist with existing scrypt slots.
//
// The `mobile` slot is a sealed box: at build time we generate an ephemeral
// P-256 keypair, ECDH it against the phone's enclave public key, HKDF the
// shared secret into a KEK, and wrap the master key. To unlock, the phone
// recomputes the same shared secret with its Secure-Enclave private key
// (SecKeyCopyKeyExchangeResult, FaceID-gated) — the private key never leaves
// the device, and only the phone can derive the KEK. See deviceUnsealMasterKey
// below for the canonical client-side reference implementation.

import {
  createCipheriv,
  createDecipheriv,
  createECDH,
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

// ─── Mobile slot (phone-approved unlock via ECDH sealed box) ─────────────────────
//
// Curve P-256 (the only curve the iOS Secure Enclave supports). Public keys
// travel as the X9.63 uncompressed point (0x04 || X || Y, 65 bytes) — exactly
// what iOS `SecKeyCopyExternalRepresentation` emits and what Node's createECDH
// produces/consumes. The shared secret is the raw ECDH X-coordinate, matching
// Apple's `SecKeyAlgorithm.ecdhKeyExchangeStandard` (cofactor is 1 on P-256, so
// standard and cofactor agree).

export const MOBILE_SLOT_ALG = "ecdh-p256-hkdf-sha256-aes256gcm";
const MOBILE_HKDF_INFO = "agent-id-vault-mobile-v1";
const MOBILE_CURVE = "prime256v1";

function mobileKek(sharedSecret, salt) {
  return Buffer.from(
    hkdfSync("sha256", sharedSecret, salt, MOBILE_HKDF_INFO, 32),
  );
}

// devicePubKeyHex: phone's enclave public key, X9.63 uncompressed (hex).
export function buildMobileSlot(id, masterKey, devicePubKeyHex, deviceId = null) {
  const devicePubKey = Buffer.from(devicePubKeyHex, "hex");
  const ephemeral = createECDH(MOBILE_CURVE);
  ephemeral.generateKeys();
  const sharedSecret = ephemeral.computeSecret(devicePubKey);
  const salt = randomBytes(SALT_BYTES);
  const kek = mobileKek(sharedSecret, salt);
  const wrap = aeadEncrypt(kek, masterKey);
  return {
    id,
    type: "mobile",
    deviceId,
    alg: MOBILE_SLOT_ALG,
    devicePubKey: devicePubKey.toString("hex"),
    ephemeralPubKey: ephemeral.getPublicKey().toString("hex"),
    salt: salt.toString("hex"),
    wrap,
  };
}

// Public material the phone needs to unseal — never includes the master key,
// only the sealed box. Safe to hand to the control plane / phone while locked.
export function mobileSlotChallenge(slot) {
  if (slot.type !== "mobile") {
    throw new Error(`Slot ${slot.id} is not a mobile slot`);
  }
  return {
    slotId: slot.id,
    deviceId: slot.deviceId || null,
    alg: slot.alg,
    devicePubKey: slot.devicePubKey,
    ephemeralPubKey: slot.ephemeralPubKey,
    salt: slot.salt,
    wrap: slot.wrap,
  };
}

// Canonical client-side reference: what the iOS app does in Swift. Given the
// device's P-256 private scalar (raw bytes — on a phone this is the Secure
// Enclave key, accessed via SecKeyCopyKeyExchangeResult and never exported),
// recompute the shared secret and unwrap the master key. Used by tests to
// stand in for the phone, and as the spec the Swift port mirrors.
export function deviceUnsealMasterKey(slot, devicePrivateKeyRaw) {
  if (slot.type !== "mobile") {
    throw new Error(`Slot ${slot.id} is not a mobile slot`);
  }
  const ecdh = createECDH(MOBILE_CURVE);
  ecdh.setPrivateKey(devicePrivateKeyRaw);
  const sharedSecret = ecdh.computeSecret(
    Buffer.from(slot.ephemeralPubKey, "hex"),
  );
  const kek = mobileKek(sharedSecret, Buffer.from(slot.salt, "hex"));
  return aeadDecrypt(kek, slot.wrap);
}

// ─── Generic ECDH sealed box (control-plane master-key transport) ────────────────
//
// Same construction as the mobile slot, used in reverse: instead of the proxy
// sealing the master key TO a phone, an approver seals the recovered master key
// BACK to the proxy's control-plane key so it never crosses the control link in
// cleartext. The proxy's public key is pinned out-of-band (the pairing QR), so a
// network attacker can't substitute their own and capture the master key.

const CONTROL_SEAL_INFO = "agent-id-control-seal-v1";

function controlSealKek(sharedSecret, salt) {
  return Buffer.from(hkdfSync("sha256", sharedSecret, salt, CONTROL_SEAL_INFO, 32));
}

// Seal `plaintext` (a Buffer, e.g. the 32-byte master key) to `recipientPubKeyHex`
// (X9.63 uncompressed P-256 point). Returns a self-describing sealed box.
export function sealToPublicKey(plaintext, recipientPubKeyHex) {
  const recipientPub = Buffer.from(recipientPubKeyHex, "hex");
  const ephemeral = createECDH(MOBILE_CURVE);
  ephemeral.generateKeys();
  const sharedSecret = ephemeral.computeSecret(recipientPub);
  const salt = randomBytes(SALT_BYTES);
  const kek = controlSealKek(sharedSecret, salt);
  const box = aeadEncrypt(kek, plaintext);
  return {
    alg: MOBILE_SLOT_ALG,
    ephemeralPubKey: ephemeral.getPublicKey().toString("hex"),
    salt: salt.toString("hex"),
    iv: box.iv,
    ct: box.ct,
    tag: box.tag,
  };
}

// Recover the plaintext from a sealed box with the recipient's P-256 private
// scalar (raw bytes). Throws on a wrong key (GCM tag mismatch) or a malformed box.
export function unsealFromPublicKey(box, recipientPrivateKeyRaw) {
  if (!box || typeof box !== "object" || !box.ephemeralPubKey || !box.salt) {
    throw new Error("malformed sealed box");
  }
  const ecdh = createECDH(MOBILE_CURVE);
  ecdh.setPrivateKey(recipientPrivateKeyRaw);
  const sharedSecret = ecdh.computeSecret(Buffer.from(box.ephemeralPubKey, "hex"));
  const kek = controlSealKek(sharedSecret, Buffer.from(box.salt, "hex"));
  return aeadDecrypt(kek, { iv: box.iv, ct: box.ct, tag: box.tag });
}

// ─── Owner-approval slot (SSO-released KEK) ──────────────────────────────────────
//
// Symmetric counterpart to the mobile slot: instead of sealing the master key to
// a phone's enclave key, the master key is wrapped by a random 32-byte KEK that
// is handed to the Alien SSO at enrollment and released only after the owner
// approves an unlock (see lib/owner-approval.mjs for the SSO client). The slot
// stores only the opaque `keyRef` the SSO returned — never the KEK itself, so a
// stolen vault file is inert without an owner-approved release.

const OWNER_APPROVAL_KEK_BYTES = 32;

export function ownerApprovalKekBytes() {
  return randomBytes(OWNER_APPROVAL_KEK_BYTES);
}

function assertOwnerApprovalKek(kek) {
  if (!Buffer.isBuffer(kek) || kek.length !== OWNER_APPROVAL_KEK_BYTES) {
    throw new Error(`owner-approval KEK must be a ${OWNER_APPROVAL_KEK_BYTES}-byte Buffer`);
  }
}

export function buildOwnerApprovalSlot(
  id,
  masterKey,
  kek,
  { keyRef, ssoBaseUrl = null, providerAddress = null } = {},
) {
  if (typeof keyRef !== "string" || !keyRef) {
    throw new Error("owner-approval slot requires a keyRef");
  }
  assertOwnerApprovalKek(kek);
  const wrap = aeadEncrypt(kek, masterKey);
  return {
    id,
    type: "owner-approval",
    keyRef,
    ssoBaseUrl: ssoBaseUrl || null,
    providerAddress: providerAddress || null,
    wrap,
  };
}

export function unwrapSlotWithOwnerApproval(slot, kek) {
  if (slot.type !== "owner-approval") {
    throw new Error(`Slot ${slot.id} is not an owner-approval slot`);
  }
  assertOwnerApprovalKek(kek);
  return aeadDecrypt(kek, slot.wrap);
}

export function findOwnerApprovalSlot(slots) {
  return slots.find((s) => s.type === "owner-approval") || null;
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

export function findMobileSlots(slots) {
  return slots.filter((s) => s.type === "mobile");
}

// Constant-time master-key compare (used in tests + unlock validation).
export function masterKeyEquals(a, b) {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
