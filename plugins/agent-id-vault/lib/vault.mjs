// Alien Agent ID — Vault facade.
//
// Single import surface for callers (CLI, proxy). Backs onto lib/format.mjs
// for crypto + file layout and lib/store.mjs for record schema.
//
// Typical flow:
//
//   const vault = await openVault({ stateDir, passphrase });
//   const cred = vault.get("github-pat");
//   vault.add({ name: "x", type: "bearer", value: "...", domains: ["api.x.com"] });
//   await vault.save();
//
// Unlock attempts agent-key slot first (fast, unattended) then falls back
// to passphrase if provided. Throws if neither works.

import fs from "node:fs/promises";

import {
  buildAgentKeySlot,
  buildMobileSlot,
  buildOwnerApprovalSlot,
  buildPassphraseSlot,
  decryptPayload,
  encryptPayload,
  findAgentKeySlot,
  findMobileSlots,
  findOwnerApprovalSlot,
  generateMasterKey,
  mobileSlotChallenge,
  newVaultFile,
  nextSlotId,
  unwrapSlotWithAgentKey,
  unwrapSlotWithOwnerApproval,
  unwrapSlotWithPassphrase,
  validateVaultHeader,
  VAULT_VERSION,
} from "./format.mjs";

import {
  addCredential,
  emptyPayload,
  getCredential,
  listMetadata,
  parsePayload,
  removeCredential,
  serializePayload,
  touchLastUsed,
  wipePayload,
} from "./store.mjs";

import {
  ensureDir,
  readJsonFile,
  setPrivateFilePermissions,
  statePaths,
} from "../../agent-id-core/lib/state.mjs";
import path from "node:path";

const VAULT_LOCKED = Symbol("vault-locked");

async function readVaultFile(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}

async function writeVaultFile(filePath, vaultFile) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, JSON.stringify(vaultFile, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
  await setPrivateFilePermissions(filePath);
}

export async function vaultFileExists(stateDir) {
  const paths = statePaths(stateDir);
  try {
    await fs.access(paths.vaultFile);
    return true;
  } catch {
    return false;
  }
}

export async function loadAgentPrivateKey(stateDir) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  return key?.privateKeyPem || null;
}

// ─── Open / unlock ──────────────────────────────────────────────────────────────

export async function openVault({
  stateDir,
  passphrase = null,
  privateKeyPem = null,
  ownerApprovalKek = null,
}) {
  const paths = statePaths(stateDir);
  const file = await readVaultFile(paths.vaultFile);
  if (!file) {
    const err = new Error(
      `Vault not found at ${paths.vaultFile}. Run \`agent-id-vault init\` first.`,
    );
    err.code = "VAULT_NOT_FOUND";
    throw err;
  }
  validateVaultHeader(file);

  let masterKey = null;
  const errors = [];

  if (privateKeyPem) {
    const slot = findAgentKeySlot(file.slots);
    if (slot) {
      try {
        masterKey = unwrapSlotWithAgentKey(slot, privateKeyPem);
      } catch (err) {
        errors.push(`agent-key slot ${slot.id}: ${err.message}`);
      }
    }
  }

  if (!masterKey && passphrase != null) {
    for (const slot of file.slots) {
      if (slot.type !== "passphrase") continue;
      try {
        masterKey = unwrapSlotWithPassphrase(slot, passphrase);
        break;
      } catch (err) {
        errors.push(`passphrase slot ${slot.id}: ${err.message}`);
      }
    }
  }

  if (!masterKey && ownerApprovalKek) {
    const slot = findOwnerApprovalSlot(file.slots);
    if (slot) {
      try {
        masterKey = unwrapSlotWithOwnerApproval(slot, ownerApprovalKek);
      } catch (err) {
        errors.push(`owner-approval slot ${slot.id}: ${err.message}`);
      }
    }
  }

  if (!masterKey) {
    const err = new Error(
      "Could not unlock vault — passphrase wrong or no usable slot. " +
        (errors.length ? `(${errors.join("; ")})` : ""),
    );
    err.code = "VAULT_UNLOCK_FAILED";
    throw err;
  }

  const payloadJson = decryptPayload(masterKey, file.payload);
  const payload = parsePayload(payloadJson);

  return buildVaultHandle({ stateDir, file, masterKey, payload });
}

// Open the vault when the master key was recovered out-of-band — e.g. the
// phone unsealed a mobile slot and handed the master key back to the proxy
// over the control plane. The bytes were already produced from a vault slot,
// so a wrong key fails the payload AEAD tag with VAULT_UNLOCK_FAILED.
export async function openVaultWithMasterKey({ stateDir, masterKey }) {
  const paths = statePaths(stateDir);
  const file = await readVaultFile(paths.vaultFile);
  if (!file) {
    const err = new Error(
      `Vault not found at ${paths.vaultFile}. Run \`agent-id-vault init\` first.`,
    );
    err.code = "VAULT_NOT_FOUND";
    throw err;
  }
  validateVaultHeader(file);

  let payload;
  try {
    payload = parsePayload(decryptPayload(masterKey, file.payload));
  } catch (err) {
    const e = new Error(`Master key did not open the vault payload: ${err.message}`);
    e.code = "VAULT_UNLOCK_FAILED";
    throw e;
  }

  return buildVaultHandle({ stateDir, file, masterKey, payload });
}

// Read the mobile-slot challenges without unlocking. The proxy hands these to
// the phone while the vault is locked; they contain only the sealed box, never
// the master key.
export async function readMobileSlotChallenges(stateDir) {
  const paths = statePaths(stateDir);
  const file = await readVaultFile(paths.vaultFile);
  if (!file) return [];
  return findMobileSlots(file.slots || []).map(mobileSlotChallenge);
}

// Read the owner-approval unlock descriptor without unlocking — only the public
// `keyRef` + SSO coordinates the approver needs to drive the unlock. The wrapped
// master key and KEK are never exposed. Returns null if no owner-approval slot.
export async function readOwnerApprovalChallenge(stateDir) {
  const paths = statePaths(stateDir);
  const file = await readVaultFile(paths.vaultFile);
  if (!file) return null;
  const slot = findOwnerApprovalSlot(file.slots || []);
  if (!slot) return null;
  return {
    slotId: slot.id,
    keyRef: slot.keyRef,
    ssoBaseUrl: slot.ssoBaseUrl || null,
    providerAddress: slot.providerAddress || null,
  };
}

// Recover the master key from an owner-approval slot given the SSO-released KEK,
// without building a vault handle. The approver (proxy CLI, or the test) POSTs
// the result to the control plane's /approve, exactly as the phone does after
// unsealing a mobile slot. The KEK is the caller's to zero afterwards.
export async function recoverMasterKeyViaOwnerApproval(stateDir, kek) {
  const paths = statePaths(stateDir);
  const file = await readVaultFile(paths.vaultFile);
  if (!file) {
    const err = new Error(`Vault not found at ${paths.vaultFile}.`);
    err.code = "VAULT_NOT_FOUND";
    throw err;
  }
  const slot = findOwnerApprovalSlot(file.slots || []);
  if (!slot) {
    const err = new Error("Vault has no owner-approval slot");
    err.code = "NO_OWNER_APPROVAL_SLOT";
    throw err;
  }
  return unwrapSlotWithOwnerApproval(slot, kek);
}

function buildVaultHandle({ stateDir, file, masterKey, payload }) {
  let state = { file, masterKey, payload };

  function assertOpen() {
    if (state === VAULT_LOCKED) throw new Error("Vault is locked");
  }

  return {
    get stateDir() {
      return stateDir;
    },
    get slots() {
      assertOpen();
      return state.file.slots.map((s) => ({
        id: s.id,
        type: s.type,
        agentId: s.agentId || null,
        deviceId: s.deviceId || null,
        keyRef: s.keyRef || null,
      }));
    },
    list() {
      assertOpen();
      return listMetadata(state.payload);
    },
    get(name) {
      assertOpen();
      return getCredential(state.payload, name);
    },
    has(name) {
      assertOpen();
      return getCredential(state.payload, name) !== null;
    },
    add(record) {
      assertOpen();
      return addCredential(state.payload, record);
    },
    remove(name) {
      assertOpen();
      return removeCredential(state.payload, name);
    },
    touchLastUsed(name) {
      assertOpen();
      touchLastUsed(state.payload, name);
    },
    addPassphraseSlot(passphrase) {
      assertOpen();
      const id = nextSlotId(state.file.slots);
      const slot = buildPassphraseSlot(id, state.masterKey, passphrase);
      state.file.slots.push(slot);
      return slot;
    },
    addAgentKeySlot(privateKeyPem, agentId = null) {
      assertOpen();
      const id = nextSlotId(state.file.slots);
      const slot = buildAgentKeySlot(id, state.masterKey, privateKeyPem, agentId);
      state.file.slots.push(slot);
      return slot;
    },
    addMobileSlot(devicePubKeyHex, deviceId = null) {
      assertOpen();
      const id = nextSlotId(state.file.slots);
      const slot = buildMobileSlot(id, state.masterKey, devicePubKeyHex, deviceId);
      state.file.slots.push(slot);
      return slot;
    },
    addOwnerApprovalSlot(kek, { keyRef, ssoBaseUrl = null, providerAddress = null } = {}) {
      assertOpen();
      const id = nextSlotId(state.file.slots);
      const slot = buildOwnerApprovalSlot(id, state.masterKey, kek, {
        keyRef,
        ssoBaseUrl,
        providerAddress,
      });
      state.file.slots.push(slot);
      return slot;
    },
    removeSlot(id) {
      assertOpen();
      if (state.file.slots.length <= 1) {
        throw new Error("Refusing to remove last slot — vault would be unrecoverable");
      }
      const before = state.file.slots.length;
      state.file.slots = state.file.slots.filter((s) => s.id !== id);
      return before !== state.file.slots.length;
    },
    async save() {
      assertOpen();
      const paths = statePaths(stateDir);
      state.file.payload = encryptPayload(state.masterKey, serializePayload(state.payload));
      await writeVaultFile(paths.vaultFile, state.file);
    },
    lock() {
      if (state !== VAULT_LOCKED) {
        state.masterKey.fill(0);
        // Drop the decrypted credential secrets too, not just the master key —
        // otherwise every bearer/cookie/password and wallet private key lingers
        // in the heap past idle-lock.
        wipePayload(state.payload);
        state = VAULT_LOCKED;
      }
    },
    raw() {
      assertOpen();
      return state.file;
    },
  };
}

// ─── Init ───────────────────────────────────────────────────────────────────────

export async function initVault({ stateDir, passphrase, privateKeyPem = null, agentId = null }) {
  const paths = statePaths(stateDir);
  const existing = await readVaultFile(paths.vaultFile);
  if (existing) {
    const err = new Error(`Vault already exists at ${paths.vaultFile}`);
    err.code = "VAULT_EXISTS";
    throw err;
  }
  if (!passphrase) {
    throw new Error("Passphrase required for slot 0");
  }
  const masterKey = generateMasterKey();
  const slots = [buildPassphraseSlot(0, masterKey, passphrase)];
  if (privateKeyPem) {
    slots.push(buildAgentKeySlot(1, masterKey, privateKeyPem, agentId));
  }
  const file = newVaultFile({
    masterKey,
    slots,
    payloadPlaintext: serializePayload(emptyPayload()),
  });
  await writeVaultFile(paths.vaultFile, file);
  return { path: paths.vaultFile, slots: file.slots.length, version: VAULT_VERSION };
}

// ─── Export / import (the file is already encrypted, so copy bytes) ─────────────

export async function exportVault({ stateDir, outPath }) {
  const paths = statePaths(stateDir);
  const data = await fs.readFile(paths.vaultFile);
  await fs.writeFile(outPath, data, { mode: 0o600 });
  return outPath;
}

export async function importVault({ stateDir, inPath, overwrite = false }) {
  const paths = statePaths(stateDir);
  if (!overwrite) {
    const existing = await readVaultFile(paths.vaultFile);
    if (existing) {
      const err = new Error(
        `Vault already exists at ${paths.vaultFile}. Use --overwrite to replace.`,
      );
      err.code = "VAULT_EXISTS";
      throw err;
    }
  }
  const data = await fs.readFile(inPath, "utf8");
  // Parse to validate it's a real vault file before clobbering anything.
  const parsed = JSON.parse(data);
  validateVaultHeader(parsed);
  await fs.writeFile(paths.vaultFile, data, { encoding: "utf8", mode: 0o600 });
  await setPrivateFilePermissions(paths.vaultFile);
  return paths.vaultFile;
}
