#!/usr/bin/env node

// Passkey vault slot: the master key is wrapped by a KEK derived (HKDF-SHA256)
// from a WebAuthn PRF secret. The browser runs the ceremony; here we exercise the
// pure crypto + the openVault / initVault / addPasskeySlot wiring with a stand-in
// PRF secret (what the authenticator would return).
//
// Run: node --test tests/test-vault-passkey.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { randomBytes, generateKeyPairSync } from "node:crypto";

import {
  buildPasskeySlot,
  unwrapSlotWithPasskey,
  generatePasskeyPrfSalt,
  generateMasterKey,
  masterKeyEquals,
} from "../plugins/agent-id-vault/lib/format.mjs";
import {
  initVault,
  openVault,
  readPasskeyChallenges,
} from "../plugins/agent-id-vault/lib/vault.mjs";

const PRF = () => randomBytes(32); // stands in for the authenticator's PRF output
const DESC = (prfSalt) => ({
  credentialId: "Y3JlZA",
  rpId: "localhost",
  prfSalt,
  deviceLabel: "Touch ID",
});

test("passkey slot wraps + unwraps the master key with the PRF secret", () => {
  const mk = generateMasterKey();
  const prf = PRF();
  const salt = generatePasskeyPrfSalt();
  const slot = buildPasskeySlot(0, mk, prf, DESC(salt));
  assert.equal(slot.type, "passkey");
  assert.equal(slot.credentialId, "Y3JlZA");
  assert.equal(slot.rpId, "localhost");
  assert.equal(slot.prfSalt, salt);
  assert.ok(!("prfSecret" in slot), "slot must NOT store the PRF secret");

  assert.ok(masterKeyEquals(unwrapSlotWithPasskey(slot, prf), mk));
  assert.throws(() => unwrapSlotWithPasskey(slot, PRF()), /./); // wrong PRF → GCM tag fail
});

test("init a passkey-only vault (no agent key) and unlock it with the PRF secret", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pk-vault-"));
  try {
    const prf = PRF();
    const salt = generatePasskeyPrfSalt();
    const res = await initVault({
      stateDir: dir,
      passkey: { prfSecret: prf, ...DESC(salt) },
    });
    assert.equal(res.mode, "user");
    assert.equal(res.slots, 1);

    // The form would read this descriptor to run the authenticate ceremony.
    const challenges = await readPasskeyChallenges(dir);
    assert.equal(challenges.length, 1);
    assert.equal(challenges[0].rpId, "localhost");
    assert.equal(challenges[0].prfSalt, salt);
    assert.ok(
      !("wrap" in challenges[0]),
      "challenge must not expose the wrapped key"
    );

    // Unlock with the PRF secret.
    const v = await openVault({ stateDir: dir, passkeyPrfSecret: prf });
    assert.equal(v.mode, "user");
    assert.ok(v.slots.some((s) => s.type === "passkey"));
    v.lock();

    // A wrong PRF secret cannot open it (and agent-key/passphrase aren't present).
    await assert.rejects(
      openVault({ stateDir: dir, passkeyPrfSecret: PRF() }),
      /unlock/i
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("addPasskeySlot adds a second unlock path to an existing vault", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pk-vault-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    await initVault({ stateDir: dir, privateKeyPem: privateKey }); // agent-key vault
    const v = await openVault({ stateDir: dir, privateKeyPem: privateKey });
    const prf = PRF();
    const salt = generatePasskeyPrfSalt();
    v.addPasskeySlot(prf, DESC(salt));
    await v.save();
    v.lock();

    // Now openable by EITHER the agent key or the passkey PRF secret.
    const viaPasskey = await openVault({
      stateDir: dir,
      passkeyPrfSecret: prf,
    });
    assert.ok(viaPasskey.slots.some((s) => s.type === "passkey"));
    viaPasskey.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
