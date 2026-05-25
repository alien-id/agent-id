#!/usr/bin/env node

// Tests for the portable vault format (slot-wrapped master key).
//
// Covers: round-trip via passphrase slot, agent-key slot, multi-slot vault,
// re-keying, slot removal, payload integrity (tag check).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  buildAgentKeySlot,
  buildPassphraseSlot,
  decryptPayload,
  encryptPayload,
  findAgentKeySlot,
  findPassphraseSlot,
  generateMasterKey,
  masterKeyEquals,
  newVaultFile,
  nextSlotId,
  unwrapSlotWithAgentKey,
  unwrapSlotWithPassphrase,
  validateVaultHeader,
} from "../plugins/agent-id-vault/lib/format.mjs";

import { generateEd25519PemPair } from "../plugins/agent-id-core/lib/crypto.mjs";

describe("vault format", () => {
  it("passphrase slot round-trips the master key", () => {
    const mk = generateMasterKey();
    const slot = buildPassphraseSlot(0, mk, "correct horse battery staple");
    const recovered = unwrapSlotWithPassphrase(slot, "correct horse battery staple");
    assert.ok(masterKeyEquals(mk, recovered));
  });

  it("passphrase slot rejects wrong passphrase", () => {
    const mk = generateMasterKey();
    const slot = buildPassphraseSlot(0, mk, "right");
    assert.throws(() => unwrapSlotWithPassphrase(slot, "wrong"));
  });

  it("agent-key slot round-trips the master key", () => {
    const mk = generateMasterKey();
    const { privateKeyPem } = generateEd25519PemPair();
    const slot = buildAgentKeySlot(1, mk, privateKeyPem, "agent-123");
    const recovered = unwrapSlotWithAgentKey(slot, privateKeyPem);
    assert.ok(masterKeyEquals(mk, recovered));
  });

  it("agent-key slot rejects a different private key", () => {
    const mk = generateMasterKey();
    const { privateKeyPem: pk1 } = generateEd25519PemPair();
    const { privateKeyPem: pk2 } = generateEd25519PemPair();
    const slot = buildAgentKeySlot(0, mk, pk1);
    assert.throws(() => unwrapSlotWithAgentKey(slot, pk2));
  });

  it("multi-slot vault has both passphrase + agent-key slots", () => {
    const mk = generateMasterKey();
    const { privateKeyPem } = generateEd25519PemPair();
    const slots = [
      buildPassphraseSlot(0, mk, "topsecret"),
      buildAgentKeySlot(1, mk, privateKeyPem),
    ];
    const file = newVaultFile({ masterKey: mk, slots, payloadPlaintext: '{"a":1}' });
    validateVaultHeader(file);
    assert.equal(findPassphraseSlot(file.slots).id, 0);
    assert.equal(findAgentKeySlot(file.slots).id, 1);
    assert.equal(nextSlotId(file.slots), 2);
  });

  it("payload round-trips via master key", () => {
    const mk = generateMasterKey();
    const encrypted = encryptPayload(mk, '{"hello":"world"}');
    const decrypted = decryptPayload(mk, encrypted);
    assert.equal(decrypted, '{"hello":"world"}');
  });

  it("payload tag detects tamper", () => {
    const mk = generateMasterKey();
    const encrypted = encryptPayload(mk, '{"hello":"world"}');
    // Flip a byte in ciphertext
    const tampered = {
      ...encrypted,
      ct: encrypted.ct.replace(/^./, (c) =>
        c === "a" ? "b" : "a",
      ),
    };
    assert.throws(() => decryptPayload(mk, tampered));
  });

  it("validateVaultHeader rejects bad magic / version", () => {
    assert.throws(() => validateVaultHeader({ magic: "wrong", version: 2, slots: [{}] }));
    assert.throws(() => validateVaultHeader({ magic: "agent-id-vault", version: 1, slots: [{}] }));
    assert.throws(() => validateVaultHeader({ magic: "agent-id-vault", version: 2, slots: [] }));
  });
});
