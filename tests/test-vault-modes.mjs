import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";

import {
  initVault,
  openVault,
  openVaultWithMasterKey,
} from "../plugins/agent-id-vault/lib/vault.mjs";
import { generateMasterKey } from "../plugins/agent-id-vault/lib/format.mjs";
import { statePaths } from "../plugins/agent-id-core/lib/state.mjs";

function agentPem() {
  const { privateKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return privateKey;
}

async function tmp() {
  return mkdtemp(path.join(os.tmpdir(), "vmode-"));
}

test("user mode: no passphrase, agent-key unlock, REFUSES a passphrase slot", async () => {
  const dir = await tmp();
  try {
    const pem = agentPem();
    const res = await initVault({ stateDir: dir, privateKeyPem: pem });
    assert.equal(res.mode, "user");
    const v = await openVault({ stateDir: dir, privateKeyPem: pem });
    assert.equal(v.mode, "user");
    // The agent cannot enable a passphrase on a user-mode vault.
    assert.throws(() => v.addPassphraseSlot("hunter2"), /only allowed in dev-mode/i);
    v.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("init with no unlock method at all is refused", async () => {
  const dir = await tmp();
  try {
    await assert.rejects(initVault({ stateDir: dir }), /at least one unlock method/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("dev mode (passphrase at init): allows adding another passphrase slot", async () => {
  const dir = await tmp();
  try {
    const res = await initVault({ stateDir: dir, passphrase: "first-pass" });
    assert.equal(res.mode, "dev");
    const v = await openVault({ stateDir: dir, passphrase: "first-pass" });
    assert.equal(v.mode, "dev");
    const slot = v.addPassphraseSlot("second-pass");
    assert.equal(slot.type, "passphrase");
    await v.save();
    v.lock();
    const v2 = await openVault({ stateDir: dir, passphrase: "second-pass" });
    assert.equal(v2.mode, "dev");
    v2.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("dev mode via --dev + agent key (no passphrase): passphrase addable later", async () => {
  const dir = await tmp();
  try {
    const pem = agentPem();
    const res = await initVault({ stateDir: dir, privateKeyPem: pem, dev: true });
    assert.equal(res.mode, "dev");
    const v = await openVault({ stateDir: dir, privateKeyPem: pem });
    v.addPassphraseSlot("added");
    await v.save();
    v.lock();
    const v2 = await openVault({ stateDir: dir, passphrase: "added" });
    assert.equal(v2.mode, "dev");
    v2.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("tampering the mode (user→dev in the file) is detected on unlock", async () => {
  const dir = await tmp();
  try {
    const pem = agentPem();
    await initVault({ stateDir: dir, privateKeyPem: pem });
    const vf = statePaths(dir).vaultFile;
    const file = JSON.parse(await readFile(vf, "utf8"));
    file.mode = "dev"; // attacker flips the cleartext header to try to allow a passphrase
    await writeFile(vf, JSON.stringify(file, null, 2));
    await assert.rejects(
      openVault({ stateDir: dir, privateKeyPem: pem }),
      /mode tag mismatch|tampered/i,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("stripping the modeTag while flipping the mode is detected (QW-3)", async () => {
  const dir = await tmp();
  try {
    const pem = agentPem();
    await initVault({ stateDir: dir, privateKeyPem: pem });
    const vf = statePaths(dir).vaultFile;
    const file = JSON.parse(await readFile(vf, "utf8"));
    // Strip the integrity tag AND flip the mode — the "legacy, skip" bypass.
    delete file.modeTag;
    file.mode = "dev";
    await writeFile(vf, JSON.stringify(file, null, 2));
    await assert.rejects(
      openVault({ stateDir: dir, privateKeyPem: pem }),
      /modeTag was stripped|tampered/i,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openVaultWithMasterKey: a wrong key is an unlock failure, not 'tampered' (QW-4)", async () => {
  const dir = await tmp();
  try {
    const pem = agentPem();
    await initVault({ stateDir: dir, privateKeyPem: pem });
    const wrongKey = generateMasterKey();
    await assert.rejects(
      openVaultWithMasterKey({ stateDir: dir, masterKey: wrongKey }),
      (err) => {
        assert.equal(err.code, "VAULT_UNLOCK_FAILED");
        return true;
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
