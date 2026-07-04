#!/usr/bin/env node

// In-process end-to-end tests of the sync protocol over a real loopback TLS
// channel: pairing with approval, bidirectional op transfer, convergence,
// tombstones, conflict journaling, refusal paths, and the vault lock.
// Run: node --test tests/test-sync-protocol.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import { ensureDir, statePaths, writeJsonFile } from "../plugins/agent-id-core/lib/state.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { connectToPeer, startSyncServer } from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import { loadSyncIdentity } from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import { runSyncSession } from "../plugins/agent-id-vault/lib/sync/protocol.mjs";
import { withVaultLock } from "../plugins/agent-id-vault/lib/sync/lock.mjs";

const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: {} };
};

// A full simulated device: stateDir + agent key + owner session + vault.
async function makeDevice(sub, label) {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `sync-${label}-`));
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const paths = statePaths(stateDir);
  await ensureDir(path.dirname(paths.mainKey));
  await writeJsonFile(paths.mainKey, { agentId: "main", ...pair });
  const idPayload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(idPayload)).toString("base64url"), "sig"].join(".");
  await writeJsonFile(paths.ownerSession, { idToken });
  await initVault({ stateDir, privateKeyPem: pair.privateKeyPem, agentId: "main" });
  return { stateDir, pair, label };
}

async function openDevice(device) {
  const vault = await openVault({ stateDir: device.stateDir, privateKeyPem: device.pair.privateKeyPem });
  const identity = await loadSyncIdentity(device.stateDir, { label: device.label });
  return { vault, identity };
}

// One full sync between two devices over loopback TLS. approve defaults to yes.
async function syncOnce(devA, devB, { approveA = async () => true, approveB = async () => true } = {}) {
  const a = await openDevice(devA);
  const b = await openDevice(devB);
  let listenerResult;
  const listenerDone = new Promise((resolve, reject) => {
    listenerResult = { resolve, reject };
  });
  listenerDone.catch(() => {}); // refusal tests reject this after the initiator throws
  const srv = await startSyncServer({
    host: "127.0.0.1",
    onSession: (session) => {
      runSyncSession({ session, vault: a.vault, identity: a.identity, approvePeer: approveA, verifyIdToken: fakeVerifyIdToken })
        .then(listenerResult.resolve, listenerResult.reject);
    },
  });
  try {
    const session = await connectToPeer({ host: "127.0.0.1", port: srv.port });
    const initiatorSummary = await runSyncSession({
      session, vault: b.vault, identity: b.identity, approvePeer: approveB, verifyIdToken: fakeVerifyIdToken,
    });
    const listenerSummary = await listenerDone;
    return { initiatorSummary, listenerSummary };
  } finally {
    await srv.close();
  }
}

async function credNames(device) {
  const { vault } = await openDevice(device);
  return vault.list().map((c) => c.name).sort();
}

describe("sync protocol", () => {
  let devA, devB;
  before(async () => {
    devA = await makeDevice("owner-1", "dev-a");
    devB = await makeDevice("owner-1", "dev-b");
  });
  after(async () => {
    for (const d of [devA, devB]) await fs.rm(d.stateDir, { recursive: true, force: true });
  });

  it("first sync pairs both devices and transfers divergent records both ways", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.add({ name: "gh-pat", type: "bearer", value: "tok-a", domains: ["api.github.com"] });
      await vault.save();
    }
    {
      const { vault } = await openDevice(devB);
      vault.add({ name: "npm-token", type: "bearer", value: "tok-b", domains: ["registry.npmjs.org"] });
      await vault.save();
    }
    const { initiatorSummary } = await syncOnce(devA, devB);
    assert.ok(initiatorSummary.received >= 1);
    assert.deepEqual(await credNames(devA), ["gh-pat", "npm-token"]);
    assert.deepEqual(await credNames(devB), ["gh-pat", "npm-token"]);
  });

  it("a remove on one device tombstones on the other", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.remove("npm-token");
      await vault.save();
    }
    await syncOnce(devA, devB);
    assert.deepEqual(await credNames(devB), ["gh-pat"]);
  });

  it("concurrent edits of one record converge and journal the loser", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.add({ name: "gh-pat", type: "bearer", value: "from-A", domains: ["api.github.com"] });
      await vault.save();
    }
    {
      const { vault } = await openDevice(devB);
      vault.add({ name: "gh-pat", type: "bearer", value: "from-B", domains: ["api.github.com"] });
      await vault.save();
    }
    await syncOnce(devA, devB);
    const a = await openDevice(devA);
    const b = await openDevice(devB);
    assert.equal(a.vault.get("gh-pat").value, b.vault.get("gh-pat").value);
    const journal = a.vault.payload().sync.conflicts;
    assert.equal(journal.length, 1);
    assert.equal(journal[0].name, "gh-pat");
    const winner = a.vault.get("gh-pat").value;
    assert.equal(journal[0].losingRecord.value, winner === "from-A" ? "from-B" : "from-A");
  });

  it("an unapproved peer is refused with approval-required and nothing changes", async () => {
    const devC = await makeDevice("owner-1", "dev-c");
    try {
      await assert.rejects(
        () => syncOnce(devA, devC, { approveA: async () => false }),
        (err) => err.code === "approval-required",
      );
      assert.deepEqual(await credNames(devC), []);
    } finally {
      await fs.rm(devC.stateDir, { recursive: true, force: true });
    }
  });

  it("a different-owner peer is refused with SYNC_OWNER_MISMATCH", async () => {
    const devX = await makeDevice("owner-EVIL", "dev-x");
    try {
      await assert.rejects(
        () => syncOnce(devA, devX),
        (err) => err.code === "SYNC_OWNER_MISMATCH" || err.code === "peer-error",
      );
    } finally {
      await fs.rm(devX.stateDir, { recursive: true, force: true });
    }
  });

  it("withVaultLock serializes and reports VAULT_BUSY when exhausted", async () => {
    await withVaultLock(devA.stateDir, async () => {
      await assert.rejects(
        () => withVaultLock(devA.stateDir, async () => {}, { retries: 1, delayMs: 10 }),
        (err) => err.code === "VAULT_BUSY",
      );
    });
    // lock released → works again
    await withVaultLock(devA.stateDir, async () => {});
  });
});
